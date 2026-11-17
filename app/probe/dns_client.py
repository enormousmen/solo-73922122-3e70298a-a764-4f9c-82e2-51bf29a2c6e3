"""异步 DNS 客户端：向显式配置的解析器发 A 记录查询，并沿 CNAME 链追踪。

刻意不使用 socket.getaddrinfo / asyncio 内置 DNS，原因：
1. 系统解析器不受白名单策略控制，且可能返回 IPv6；
2. 我们要求拿到 *完整* 的应答地址列表逐个校验，而不是让运行时
   自行挑选一个连接（运行时重试可能在检查后换到未获准地址）。

别名（CNAME）安全模型：
* 后续每一跳查询仍然只发给配置的解析器，绝不向应答里出现的名字
  “自举”使用其他解析器；
* 只有从请求域名沿 CNAME 链可追溯的属主名下的 A 记录，才会被当作
  目标地址；应答中夹带的其他域名 A 记录一律判为“归属不符”并整体拒绝；
* 别名链断裂（链尾无 A）、成环、超过有界跳数都会给出明确原因，
  且在任何连接尝试之前终止。
"""

from __future__ import annotations

import asyncio
import os
import random
from dataclasses import dataclass, field

from . import dns_wire
from .policy import PolicyError, is_ip_literal

# CNAME 别名跳数的硬上界与默认值：默认 8 跳（与主流解析器相当），
# 最大只允许配置到 16，防止恶意超长链放大查询流量。
DEFAULT_MAX_CNAME_HOPS = 8
HARD_MAX_CNAME_HOPS = 16


class DnsError(PolicyError):
    """解析失败（超时、SERVFAIL、NXDOMAIN、别名链异常、归属不符等）。"""

    def __init__(self, message: str, partial: "ResolutionResult | None" = None) -> None:
        super().__init__(message)
        # 失败时已收集到的链路信息（可能为 None），供探测报告展示
        self.partial = partial


@dataclass
class ResolutionResult:
    """一次主机名解析的完整结果（含别名链审计信息）。"""

    requested_name: str
    # 从请求域名开始的 CNAME 链，如 ["a.example", "cdn.example", "edge.example"]；
    # 无别名时只含请求域名本身
    cname_chain: list[str] = field(default_factory=list)
    # 沿链可追溯的全部 A 地址（去重保序）——唯一允许用于连接的地址集合
    addresses: list[str] = field(default_factory=list)
    # 本次解析实际向配置解析器发出的全部查询名（审计用）
    queried_names: list[str] = field(default_factory=list)
    # 应答段中出现过、但不属于 CNAME 链属主的 A 记录（夹带地址，仅用于报告）
    foreign_a_records: list[str] = field(default_factory=list)

    @property
    def final_name(self) -> str:
        return self.cname_chain[-1] if self.cname_chain else self.requested_name


class DnsResolver:
    def __init__(
        self,
        server_ip: str,
        port: int = 53,
        timeout: float = 3.0,
        retries: int = 1,
        max_cname_hops: int = DEFAULT_MAX_CNAME_HOPS,
    ) -> None:
        if not is_ip_literal(server_ip):
            raise ValueError("DNS 解析器必须配置为 IP 字面量，避免自举解析")
        if not 0 <= max_cname_hops <= HARD_MAX_CNAME_HOPS:
            raise ValueError(
                f"max_cname_hops 必须在 0..{HARD_MAX_CNAME_HOPS} 之间"
            )
        self._server = (server_ip, port)
        self._timeout = timeout
        self._retries = retries
        self._max_cname_hops = max_cname_hops

    async def resolve_a(self, hostname: str) -> list[str]:
        """兼容旧接口：返回沿 CNAME 链可追溯的 A 地址列表。"""
        result = await self.resolve_with_chain(hostname)
        return result.addresses

    async def resolve_with_chain(self, hostname: str) -> ResolutionResult:
        """解析主机名，追踪完整 CNAME 链并校验每条应答的属主归属。"""
        start = hostname.lower().rstrip(".")
        result = ResolutionResult(
            requested_name=start, cname_chain=[start], queried_names=[]
        )
        current = start
        jumps = 0  # 已跟随的 CNAME 跳数

        while True:
            result.queried_names.append(current)
            msg = await self._query_with_retry(current, result)

            # 1) 问题段必须与本次查询严格一致，防止答非所问
            self._check_question(msg, current)

            if msg.rcode == dns_wire.RCODE_NAME_ERROR:
                raise DnsError(
                    f"DNS NXDOMAIN: 域名 {current!r} 不存在"
                    + self._chain_suffix(result),
                    partial=result,
                )
            if msg.rcode != dns_wire.RCODE_OK:
                raise DnsError(
                    f"DNS 应答错误 rcode={msg.rcode}（域名 {current!r}）"
                    + self._chain_suffix(result),
                    partial=result,
                )

            # 2) 属主归属校验 + 本应答内的 CNAME 链推进
            local_chain, tip_ips, foreign = self._partition_answer(
                msg, current, result
            )
            for ip in foreign:
                if ip not in result.foreign_a_records:
                    result.foreign_a_records.append(ip)

            # 3) 跳数上界对“本应答内的 CNAME”同样生效（无论链尾 A 是否在同一应答）
            if local_chain:
                if jumps + len(local_chain) > self._max_cname_hops:
                    raise DnsError(
                        f"CNAME 别名链超过有界跳数上限 {self._max_cname_hops}"
                        f"（当前链: {' -> '.join(result.cname_chain)}）",
                        partial=result,
                    )
                current = local_chain[-1]
                jumps += len(local_chain)

            if tip_ips:
                for ip in tip_ips:
                    if ip not in result.addresses:
                        result.addresses.append(ip)
                # 链尾取得 A 记录：解析完成（夹带地址已在上面记录并判错，
                # 能走到这里说明没有外属主记录）
                return result

            # 4) 本应答没有 A：CNAME 目标需要继续向同一配置解析器查询
            if not local_chain:
                raise DnsError(
                    f"别名链断裂: {current!r} 的应答没有可用的 A 记录"
                    + self._chain_suffix(result),
                    partial=result,
                )

    # ------------------------------------------------------------- 内部工具
    def _partition_answer(
        self,
        msg: dns_wire.DnsMessage,
        queried_name: str,
        result: ResolutionResult,
    ) -> tuple[list[str], list[str], list[str]]:
        """校验一条应答的属主归属，并沿 CNAME 链推进。

        返回 (本应答内新走过的 CNAME 目标序列, 链尾属主的 A 地址,
        外属主夹带的 A 地址)。本应答内走过的别名会在归属校验前并入
        ``result.cname_chain``（成环在并入前拦截，不会产生重复节点）。
        任何归属/结构异常直接抛 DnsError（不向错误服务发请求）。
        """
        a_by_owner = msg.a_records_by_owner()
        cname_by_owner = msg.cname_targets_by_owner()

        # 同一属主出现多条 CNAME：线协议上非法
        seen_cname_owners: set[str] = set()
        for rec in msg.answers:
            if rec.rtype == dns_wire.TYPE_CNAME and rec.rclass == dns_wire.CLASS_IN:
                owner = rec.name.lower().rstrip(".")
                if owner in seen_cname_owners:
                    raise DnsError(
                        f"DNS 应答中属主 {owner!r} 存在多条 CNAME 记录，协议非法",
                        partial=result,
                    )
                seen_cname_owners.add(owner)

        # 先从本次查询名开始，沿本应答内的 CNAME 走到链尾
        cur = queried_name
        local_chain: list[str] = []
        while cur in cname_by_owner:
            target = cname_by_owner[cur].lower().rstrip(".")
            if not target:
                raise DnsError(f"属主 {cur!r} 的 CNAME 目标为空", partial=result)
            if target in result.cname_chain or target in local_chain:
                raise DnsError(
                    "CNAME 别名链成环: "
                    + " -> ".join(result.cname_chain + local_chain + [target]),
                    partial=result,
                )
            local_chain.append(target)
            cur = target

        # 本应答内走过的别名先并入链路，供后续归属校验与错误报告使用；
        # 成环已在上面拦截，因此这里不会引入重复节点。
        if local_chain:
            result.cname_chain.extend(local_chain)

        # 属主归属：应答里的 A/CNAME 属主必须位于已追踪链路
        # （local_chain 已在上面并入 result.cname_chain）
        traceable = set(result.cname_chain)
        foreign: list[str] = []
        for owner, ips in a_by_owner.items():
            if owner not in traceable:
                foreign.extend(ips)
        for owner in cname_by_owner:
            if owner not in traceable:
                raise DnsError(
                    f"DNS 应答归属不符: 收到与请求域名 {result.requested_name!r} "
                    f"的 CNAME 链无关的 CNAME 属主 {owner!r}，拒绝使用该应答",
                    partial=result,
                )
        if foreign:
            # 先把夹带地址记入审计字段，再整体拒绝（调用方拿不到任何可连地址）
            for ip in foreign:
                if ip not in result.foreign_a_records:
                    result.foreign_a_records.append(ip)
            raise DnsError(
                "DNS 应答夹带非别名链属主的 A 记录: "
                + ", ".join(foreign)
                + f"（请求域名 {result.requested_name!r} 的可追踪链: "
                + " -> ".join(result.cname_chain)
                + "）；这些地址不属目标域名，整体拒绝",
                partial=result,
            )

        # CNAME 与 A 不能同时挂在同一属主下（RFC 1034）
        for owner in cname_by_owner:
            if owner in a_by_owner:
                raise DnsError(
                    f"DNS 应答中属主 {owner!r} 同时存在 CNAME 与 A 记录，协议非法",
                    partial=result,
                )

        tip_ips = a_by_owner.get(cur, [])
        return local_chain, list(tip_ips), foreign

    def _check_question(self, msg: dns_wire.DnsMessage, queried_name: str) -> None:
        if len(msg.questions) != 1:
            raise DnsError(
                f"DNS 应答问题段数量异常（期望 1，实际 {len(msg.questions)}）"
            )
        q = msg.questions[0]
        if (
            q.qname.lower().rstrip(".") != queried_name
            or q.qtype != dns_wire.TYPE_A
            or q.qclass != dns_wire.CLASS_IN
        ):
            raise DnsError(
                "DNS 应答问题段与查询不符: "
                f"查询 {queried_name!r}/A/IN，应答 {q.qname!r}/{q.qtype}/{q.qclass}"
            )

    async def _query_with_retry(
        self, hostname: str, result: ResolutionResult
    ) -> dns_wire.DnsMessage:
        last_error: Exception | None = None
        for _attempt in range(self._retries + 1):
            qid = random.randint(0, 65535)
            packet = dns_wire.build_query(hostname, qid)
            try:
                data = await self._exchange(packet, qid, hostname)
            except DnsError as exc:
                last_error = exc
                continue
            try:
                return dns_wire.parse_message(data)
            except dns_wire.DnsProtocolError as exc:
                raise DnsError(f"DNS 应答解析失败: {exc}", partial=result) from exc
        raise DnsError(
            f"DNS 查询 {hostname!r} 在 {self._retries + 1} 次尝试后仍失败: {last_error}",
            partial=result,
        )

    def _chain_suffix(self, result: ResolutionResult) -> str:
        if len(result.cname_chain) <= 1:
            return ""
        return "（CNAME 链: " + " -> ".join(result.cname_chain) + "）"

    async def _exchange(self, packet: bytes, qid: int, hostname: str) -> bytes:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: _UdpClient(future, qid, hostname),
                remote_addr=self._server,
            ),
            timeout=self._timeout,
        )
        try:
            transport.sendto(packet)
            return await asyncio.wait_for(future, timeout=self._timeout)
        except asyncio.TimeoutError as exc:
            raise DnsError(
                f"DNS 查询超时（解析器 {self._server[0]}:{self._server[1]}）"
            ) from exc
        finally:
            transport.close()


class _UdpClient(asyncio.DatagramProtocol):
    def __init__(self, future: "asyncio.Future[bytes]", qid: int, hostname: str) -> None:
        self._future = future
        self._qid = qid
        self._hostname = hostname

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        if self._future.done():
            return
        if len(data) < 2 or int.from_bytes(data[:2], "big") != self._qid:
            return
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(DnsError(f"DNS socket 错误: {exc}"))


def resolver_from_env() -> DnsResolver:
    server = os.getenv("DNS_SERVER", "127.0.0.1").strip()
    port = int(os.getenv("DNS_PORT", "53"))
    timeout = float(os.getenv("DNS_TIMEOUT", "3.0"))
    retries = int(os.getenv("DNS_RETRIES", "1"))
    max_cname_hops = int(os.getenv("MAX_CNAME_HOPS", str(DEFAULT_MAX_CNAME_HOPS)))
    return DnsResolver(
        server,
        port=port,
        timeout=timeout,
        retries=retries,
        max_cname_hops=max_cname_hops,
    )

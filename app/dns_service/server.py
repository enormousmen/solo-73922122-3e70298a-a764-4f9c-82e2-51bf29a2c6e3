"""本地演示 DNS 服务（UDP/53 + 控制面 HTTP/8053）。

解析数据按“场景 profile”组织，可通过 HTTP 控制面随时热切换，
用于演示“检查后换址”（DNS rebinding 类场景）与 CNAME 别名安全：
  * profile=allowed 时域名解析到允许网段的目标；
  * 切换到 swapped 后同名域名解析到禁止网段，探测必须在连接前拦截；
  * profile=mixed 时一次应答同时包含允许与禁止地址，整体拒绝；
  * profile=alias 演示正常 CNAME 别名（单跳/多跳/链尾多 A），
    探测应沿链追踪后正常探测；
  * profile=cname-smuggle 演示 CNAME 应答夹带外域名 A、断链、成环、
    超跳数，探测必须在连接前按原因拦截。

zone 条目支持三种写法（加载时统一规范化为记录列表）：
  ["172.31.10.10"]                       # 传统：属主自身的 A 记录列表
  {"cname": "target.demo.test"}          # 简写：属主的单条 CNAME
  [{"type": "CNAME", "value": "x"},
   {"type": "A", "name": "x", "value": "172.31.10.10"},
   {"type": "A", "name": "other.demo.test", "value": "172.31.20.10"}]  # 完整结构

只实现 A/CNAME 记录；未知域名返回 NXDOMAIN；非 A 查询返回 SERVFAIL。
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from ..probe import dns_wire

PROFILES_DIR = Path(os.getenv("DNS_PROFILES_DIR", "/app/dns-profiles"))
STATE_FILE = Path(os.getenv("DNS_STATE_FILE", "/tmp/dns-state/profile"))
CONTROL_PORT = int(os.getenv("DNS_CONTROL_PORT", "8053"))


def normalize_records(owner: str, entry) -> list[dict]:
    """把 profile 中的 zone 条目统一成显式记录列表。

    输出元素形如 {"type": "A"/"CNAME", "name": 属主, "value": ...}。
    """
    owner = owner.lower().rstrip(".")
    if isinstance(entry, dict):
        # 简写：{"cname": "...", "a": [...](可选)}
        records: list[dict] = []
        cname = entry.get("cname")
        if cname:
            records.append(
                {"type": "CNAME", "name": owner, "value": str(cname).lower()}
            )
        for ip in entry.get("a", []) or []:
            records.append({"type": "A", "name": owner, "value": str(ip)})
        if not records:
            raise ValueError(f"zone {owner!r} 的简写条目既无 cname 也无 a")
        return records
    if isinstance(entry, list) and entry and all(isinstance(x, str) for x in entry):
        # 传统：纯 IP 列表 = 属主自身的 A 记录
        return [{"type": "A", "name": owner, "value": ip} for ip in entry]
    if isinstance(entry, list):
        records = []
        for item in entry:
            if not isinstance(item, dict) or "type" not in item or "value" not in item:
                raise ValueError(f"zone {owner!r} 含非法记录: {item!r}")
            records.append(
                {
                    "type": str(item["type"]).upper(),
                    "name": str(item.get("name", owner)).lower().rstrip("."),
                    "value": str(item["value"]).lower(),
                }
            )
        return records
    raise ValueError(f"zone {owner!r} 的条目格式无法识别: {entry!r}")


class ProfileStore:
    def __init__(self) -> None:
        # 规范化后：profile -> {zone_name: [record, ...]}
        self._profiles: dict[str, dict[str, list[dict]]] = {}
        self._active = ""
        self._lock = asyncio.Lock()
        self._load()
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        saved = STATE_FILE.read_text().strip() if STATE_FILE.exists() else ""
        self._active = saved if saved in self._profiles else next(iter(self._profiles))
        STATE_FILE.write_text(self._active)

    def _load(self) -> None:
        for path in sorted(PROFILES_DIR.glob("*.json")):
            data = json.loads(path.read_text())
            name = data["profile"]
            zones: dict[str, list[dict]] = {}
            for raw_name, entry in data["zones"].items():
                qname = raw_name.lower().rstrip(".")
                zones[qname] = normalize_records(qname, entry)
            self._profiles[name] = zones

    @property
    def active(self) -> str:
        return self._active

    def list_profiles(self) -> dict:
        return {name: dict(zones) for name, zones in self._profiles.items()}

    def lookup(self, qname: str) -> tuple[int, list[dict]]:
        qname = qname.lower().rstrip(".")
        zones = self._profiles[self._active]
        if qname in zones:
            return dns_wire.RCODE_OK, zones[qname]
        # 支持通配后缀（如 *.demo.test）
        for suffix, records in zones.items():
            if suffix.startswith("*.") and qname.endswith(suffix[1:]):
                return dns_wire.RCODE_OK, records
        return dns_wire.RCODE_NAME_ERROR, []

    async def switch(self, name: str) -> bool:
        async with self._lock:
            if name not in self._profiles:
                return False
            self._active = name
            STATE_FILE.write_text(name)
            return True


class DnsUdpServer(asyncio.DatagramProtocol):
    def __init__(self, store: ProfileStore) -> None:
        self._store = store
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        try:
            msg = dns_wire.parse_message(data, require_qr=False)
            question = msg.questions[0] if msg.questions else None
            if question is None or question.qtype != dns_wire.TYPE_A:
                reply = dns_wire.build_response(
                    msg.qid, question, rcode=dns_wire.RCODE_SERVFAIL
                )
            else:
                rcode, records = self._store.lookup(question.qname)
                reply = dns_wire.build_response_from_records(
                    msg.qid, question, rcode=rcode, records=records
                )
        except (dns_wire.DnsProtocolError, IndexError, ValueError):
            reply = b""
        if reply and self._transport is not None:
            self._transport.sendto(reply, addr)


async def _control_app(store: ProfileStore) -> "asyncio.base_events.Server":
    from aiohttp import web  # 延迟导入，仅 DNS 服务需要

    async def get_profiles(_request):
        return web.json_response(
            {"active": store.active, "profiles": store.list_profiles()}
        )

    async def switch(request):
        body = await request.json()
        name = str(body.get("profile", ""))
        if await store.switch(name):
            return web.json_response(
                {"active": store.active, "profiles": store.list_profiles()}
            )
        return web.json_response(
            {"error": f"未知 profile: {name!r}",
             "available": list(store.list_profiles())},
            status=404,
        )

    app = web.Application()
    app.router.add_get("/profiles", get_profiles)
    app.router.add_post("/profiles/switch", switch)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", CONTROL_PORT)
    await site.start()
    return site


async def serve() -> None:
    store = ProfileStore()
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: DnsUdpServer(store),
        local_addr=("0.0.0.0", 53),
    )
    await _control_app(store)
    print(
        f"[dns-service] UDP/53 已启动，初始 profile={store.active!r}，"
        f"控制面 HTTP/{CONTROL_PORT}",
        flush=True,
    )
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(serve())

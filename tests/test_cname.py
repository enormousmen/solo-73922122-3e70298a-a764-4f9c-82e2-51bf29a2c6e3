"""CNAME 别名解析与出站准入的安全测试。

覆盖需求关键点：
* 只有从请求域名沿 CNAME 链可追溯的 A 地址才会用于连接；
* 后续查询仍只发给配置的解析器，完整取得目标地址后全部过 CIDR 白名单；
* 夹带外域名 A（无论地址本身是否在白名单内）都判“归属不符”并整体拒绝；
* 别名链断裂、成环、超有界跳数均报告原因且不发任何连接；
* 正常别名（单跳/多跳/链尾多 A/HTTPS）仍可探测；
* 逐跳重定向校验、已批准地址重试、原域名证书校验保持不变。
"""

from __future__ import annotations

import sys

import pytest

from app.probe import dns_wire

from tests.conftest import FakeDns


@pytest.fixture(autouse=True)
def _refresh_dns_classes():
    # test_api 会 importlib.reload dns_client 模块；每个用例运行前刷新别名，
    # 避免 reload 前后类身份不一致导致 isinstance/raises 失配
    fresh = sys.modules["app.probe.dns_client"]
    globals()["DnsError"] = fresh.DnsError
    globals()["DnsResolver"] = fresh.DnsResolver
    yield


DnsError = sys.modules["app.probe.dns_client"].DnsError
DnsResolver = sys.modules["app.probe.dns_client"].DnsResolver


def _cname(owner: str, target: str) -> dict:
    return {"type": "CNAME", "name": owner, "value": target}


def _a(owner: str, ip: str) -> dict:
    return {"type": "A", "name": owner, "value": ip}


# ------------------------------------------------------------ 解析器单元测试
class TestCnameResolution:
    async def test_plain_a_unchanged(self, fake_dns, make_prober):
        fake_dns.set_zones({"plain.test": ["127.0.0.1"]})
        resolver: DnsResolver = make_prober()._resolver
        result = await resolver.resolve_with_chain("plain.test")
        assert result.addresses == ["127.0.0.1"]
        assert result.cname_chain == ["plain.test"]
        assert result.queried_names == ["plain.test"]
        assert result.foreign_a_records == []

    async def test_single_cname_chain_in_one_reply(self, fake_dns, make_prober):
        # 单条应答内同时给出 CNAME 与链尾 A
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "real.test"),
                _a("real.test", "127.0.0.1"),
            ],
        })
        resolver = make_prober()._resolver
        result = await resolver.resolve_with_chain("alias.test")
        assert result.addresses == ["127.0.0.1"]
        assert result.cname_chain == ["alias.test", "real.test"]
        assert result.queried_names == ["alias.test"]

    async def test_multi_query_cname_chain_uses_configured_resolver(
        self, fake_dns, make_prober
    ):
        # 每跳一个应答：后续查询必须仍然打到同一个假解析器
        fake_dns.set_zones({
            "a.test": [_cname("a.test", "b.test")],
            "b.test": [_cname("b.test", "c.test")],
            "c.test": [_a("c.test", "127.0.0.1")],
        })
        resolver = make_prober()._resolver
        result = await resolver.resolve_with_chain("a.test")
        assert result.addresses == ["127.0.0.1"]
        assert result.cname_chain == ["a.test", "b.test", "c.test"]
        assert result.queried_names == ["a.test", "b.test", "c.test"]
        assert fake_dns.queried_names == ["a.test", "b.test", "c.test"]

    async def test_chain_tip_multiple_a_all_returned(self, fake_dns, make_prober):
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "multi.test"),
                _a("multi.test", "127.0.0.2"),
                _a("multi.test", "127.0.0.1"),
            ],
        })
        resolver = make_prober()._resolver
        result = await resolver.resolve_with_chain("alias.test")
        assert result.addresses == ["127.0.0.2", "127.0.0.1"]

    async def test_smuggled_denied_a_rejected(self, fake_dns, make_prober):
        # CNAME 链本身合法、链尾 A 也合法，但夹带了外属主的禁止地址
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "real.test"),
                _a("real.test", "127.0.0.1"),
                _a("evil.test", "8.8.8.8"),
            ],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="夹带") as exc_info:
            await resolver.resolve_with_chain("alias.test")
        assert "8.8.8.8" in str(exc_info.value)
        assert exc_info.value.partial is not None
        assert exc_info.value.partial.foreign_a_records == ["8.8.8.8"]
        # 链尾合法地址不能作为部分结果返回给连接层
        assert exc_info.value.partial.addresses == []

    async def test_smuggled_allowed_a_also_rejected(self, fake_dns, make_prober):
        # 夹带的地址即便本身落在白名单内，也因归属不符被拒绝：
        # 不能让“外域名的地址”被当作目标地址连接
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "real.test"),
                _a("real.test", "127.0.0.1"),
                _a("foreign.test", "127.0.0.2"),
            ],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="夹带"):
            await resolver.resolve_with_chain("alias.test")

    async def test_foreign_a_without_cname_rejected(self, fake_dns, make_prober):
        # 没有 CNAME，但应答里混入其他属主的 A
        fake_dns.set_zones({
            "host.test": [
                _a("host.test", "127.0.0.1"),
                _a("other.test", "8.8.8.8"),
            ],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="夹带"):
            await resolver.resolve_with_chain("host.test")

    async def test_foreign_cname_owner_rejected(self, fake_dns, make_prober):
        # 与请求链完全无关的 CNAME 属主
        fake_dns.set_zones({
            "host.test": [
                _a("host.test", "127.0.0.1"),
                _cname("stranger.test", "evil.test"),
            ],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="归属不符"):
            await resolver.resolve_with_chain("host.test")

    async def test_broken_chain_reported(self, fake_dns, make_prober):
        # CNAME 指向的下一个名字 NXDOMAIN
        fake_dns.set_zones({
            "alias.test": [_cname("alias.test", "gone.test")],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="NXDOMAIN") as exc_info:
            await resolver.resolve_with_chain("alias.test")
        assert exc_info.value.partial is not None
        assert exc_info.value.partial.cname_chain == ["alias.test", "gone.test"]

    async def test_broken_chain_no_a_at_tip(self, fake_dns, make_prober):
        # CNAME 目标存在但应答里既无 A 也无后续 CNAME（rcode=OK 的空应答）
        fake_dns.set_zones({
            "alias.test": [_cname("alias.test", "empty.test")],
            "empty.test": [_cname("empty.test", "dead.test")],
            # 显式空记录列表：假解析器以 rcode=OK、0 应答返回，区别于 NXDOMAIN
            "dead.test": [],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="别名链断裂"):
            await resolver.resolve_with_chain("alias.test")

    async def test_empty_ok_answer_is_broken_chain(self, fake_dns, make_prober):
        # 直接查询名返回 rcode=OK 但 0 应答：按别名链断裂/无 A 处理
        fake_dns.set_zones({"empty.test": []})
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="别名链断裂"):
            await resolver.resolve_with_chain("empty.test")

    async def test_all_followup_queries_go_to_configured_resolver(
        self, fake_dns, make_prober
    ):
        # 三跳链：每个后续名字都必须由同一个假解析器（即配置解析器）回答
        fake_dns.set_zones({
            "x1.test": [_cname("x1.test", "x2.test")],
            "x2.test": [_cname("x2.test", "x3.test")],
            "x3.test": [_a("x3.test", "127.0.0.1")],
        })
        resolver = make_prober()._resolver
        result = await resolver.resolve_with_chain("x1.test")
        assert result.queried_names == ["x1.test", "x2.test", "x3.test"]
        assert fake_dns.queried_names == ["x1.test", "x2.test", "x3.test"]

    async def test_cname_loop_same_reply_rejected(self, fake_dns, make_prober):
        fake_dns.set_zones({
            "cyc.test": [
                _cname("cyc.test", "cyc2.test"),
                _cname("cyc2.test", "cyc.test"),
            ],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="成环"):
            await resolver.resolve_with_chain("cyc.test")

    async def test_cname_loop_across_queries_rejected(self, fake_dns, make_prober):
        fake_dns.set_zones({
            "cyc-a.test": [_cname("cyc-a.test", "cyc-b.test")],
            "cyc-b.test": [_cname("cyc-b.test", "cyc-a.test")],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="成环"):
            await resolver.resolve_with_chain("cyc-a.test")
        # 成环检测必须在有界查询内终止
        assert fake_dns.queried_names.count("cyc-a.test") <= 2

    async def test_cname_hop_limit_enforced(self, fake_dns, make_prober):
        zones = {f"n{i}.test": [_cname(f"n{i}.test", f"n{i + 1}.test")]
                 for i in range(10)}
        zones["n10.test"] = [_a("n10.test", "127.0.0.1")]
        fake_dns.set_zones(zones)
        resolver = DnsResolver(
            "127.0.0.1", port=fake_dns.port, retries=0, max_cname_hops=3
        )
        with pytest.raises(DnsError, match="有界跳数"):
            await resolver.resolve_with_chain("n0.test")

    async def test_zero_hop_rejects_any_alias(self, fake_dns):
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "real.test"),
                _a("real.test", "127.0.0.1"),
            ],
        })
        resolver = DnsResolver(
            "127.0.0.1", port=fake_dns.port, retries=0, max_cname_hops=0
        )
        with pytest.raises(DnsError, match="有界跳数"):
            await resolver.resolve_with_chain("alias.test")

    async def test_cname_and_a_same_owner_rejected(self, fake_dns, make_prober):
        fake_dns.set_zones({
            "host.test": [
                _cname("host.test", "real.test"),
                _a("host.test", "127.0.0.1"),
            ],
        })
        resolver = make_prober()._resolver
        with pytest.raises(DnsError, match="同时存在 CNAME 与 A"):
            await resolver.resolve_with_chain("host.test")

    async def test_question_mismatch_rejected(self, fake_dns, make_prober):
        # 手工构造答非所问的应答（问题段是 a.test，属主却是 other.test 的 A）
        original_datagram = fake_dns.datagram_received

        def wrong_question_reply(data: bytes, addr) -> None:
            msg = dns_wire.parse_message(data, require_qr=False)
            wrong_q = dns_wire.DnsQuestion("other.test")
            reply = dns_wire.build_response(msg.qid, wrong_q, answers=["127.0.0.1"])
            fake_dns._transport.sendto(reply, addr)

        fake_dns.datagram_received = wrong_question_reply  # type: ignore[method-assign]
        try:
            resolver = make_prober()._resolver
            with pytest.raises(DnsError, match="问题段与查询不符"):
                await resolver.resolve_with_chain("a.test")
        finally:
            fake_dns.datagram_received = original_datagram  # type: ignore[method-assign]


# ------------------------------------------------------- 端到端探测引擎测试
class TestProbeWithCname:
    async def test_normal_alias_still_probes(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "real.test"),
                _a("real.test", "127.0.0.1"),
            ],
        })
        http_server.route("alias.test", "/")
        prober = make_prober()

        hops = await prober.probe(f"http://alias.test:{http_server.port}/")

        hop = hops[-1]
        assert hop.outcome == "ok"
        assert hop.cname_chain == ["alias.test", "real.test"]
        assert hop.resolved_addresses == ["127.0.0.1"]
        assert hop.approved_addresses == ["127.0.0.1"]
        assert hop.connected_peer == f"127.0.0.1:{http_server.port}"
        assert hop.request_sent is True
        assert http_server.requests[-1]["host"] == "alias.test"

    async def test_multi_hop_alias_probes(self, fake_dns, http_server, make_prober):
        fake_dns.set_zones({
            "a.test": [_cname("a.test", "b.test")],
            "b.test": [_cname("b.test", "c.test")],
            "c.test": [_a("c.test", "127.0.0.1")],
        })
        http_server.route("a.test", "/")
        prober = make_prober()
        hops = await prober.probe(f"http://a.test:{http_server.port}/")
        assert hops[-1].outcome == "ok"
        assert hops[-1].cname_chain == ["a.test", "b.test", "c.test"]
        assert hops[-1].connected_peer == f"127.0.0.1:{http_server.port}"

    async def test_smuggled_denied_address_no_connection(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "real.test"),
                _a("real.test", "127.0.0.1"),
                _a("evil.test", "8.8.8.8"),
            ],
        })
        http_server.route("alias.test", "/")
        prober = make_prober()
        before = len(http_server.requests)

        hops = await prober.probe(f"http://alias.test:{http_server.port}/")

        hop = hops[-1]
        assert hop.outcome == "blocked"
        assert "夹带" in (hop.reject_reason or "")
        assert hop.connected_peer is None
        assert hop.request_sent is False
        assert hop.approved_addresses == []
        assert hop.foreign_a_records == ["8.8.8.8"]
        assert hop.cname_chain == ["alias.test", "real.test"]
        assert len(http_server.requests) == before  # 没有任何连接发出

    async def test_smuggled_allowed_address_no_connection(
        self, fake_dns, http_server, make_prober
    ):
        # 夹带地址恰好在白名单内：归属不符仍必须整体拒绝
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "real.test"),
                _a("real.test", "127.0.0.1"),
                _a("foreign.test", "127.0.0.2"),
            ],
        })
        prober = make_prober(allowed=("127.0.0.0/24",))
        before = len(http_server.requests)
        hops = await prober.probe(f"http://alias.test:{http_server.port}/")
        assert hops[-1].outcome == "blocked"
        assert "夹带" in (hops[-1].reject_reason or "")
        assert hops[-1].connected_peer is None
        assert len(http_server.requests) == before

    async def test_alias_chain_tip_denied_cidr_blocks(
        self, fake_dns, http_server, make_prober
    ):
        # 链完全合法，但链尾地址在白名单外：走原有“全或无”CIDR 拒绝
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "real.test"),
                _a("real.test", "8.8.8.8"),
            ],
        })
        prober = make_prober()
        hops = await prober.probe(f"http://alias.test:{http_server.port}/")
        assert hops[-1].outcome == "blocked"
        assert "白名单" in (hops[-1].reject_reason or "")
        assert hops[-1].connected_peer is None
        assert hops[-1].request_sent is False
        assert hops[-1].resolved_addresses == ["8.8.8.8"]

    async def test_alias_tip_mixed_a_full_rejection(
        self, fake_dns, http_server, make_prober
    ):
        # 链尾多 A 中含禁止地址：全部获准才连接，整体拒绝
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "multi.test"),
                _a("multi.test", "127.0.0.1"),
                _a("multi.test", "8.8.8.8"),
            ],
        })
        prober = make_prober()
        hops = await prober.probe(f"http://alias.test:{http_server.port}/")
        assert hops[-1].outcome == "blocked"
        assert "整体拒绝" in (hops[-1].reject_reason or "")
        assert hops[-1].connected_peer is None

    async def test_alias_failover_within_approved_only(
        self, fake_dns, http_server, make_prober
    ):
        # 链尾两个已批准地址，第一个无服务，重试只能在已批准集合内
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "multi.test"),
                _a("multi.test", "127.0.0.2"),
                _a("multi.test", "127.0.0.1"),
            ],
        })
        http_server.route("alias.test", "/")
        prober = make_prober(allowed=("127.0.0.0/24",))
        hops = await prober.probe(f"http://alias.test:{http_server.port}/")
        hop = hops[-1]
        assert hop.outcome == "ok"
        assert hop.connected_peer == f"127.0.0.1:{http_server.port}"
        assert hop.resolved_addresses == ["127.0.0.2", "127.0.0.1"]

    async def test_alias_loop_reported_without_request(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({
            "cyc-a.test": [_cname("cyc-a.test", "cyc-b.test")],
            "cyc-b.test": [_cname("cyc-b.test", "cyc-a.test")],
        })
        prober = make_prober()
        before = len(http_server.requests)
        hops = await prober.probe(f"http://cyc-a.test:{http_server.port}/")
        assert hops[-1].outcome == "blocked"
        assert "成环" in (hops[-1].reject_reason or "")
        assert hops[-1].connected_peer is None
        assert hops[-1].request_sent is False
        assert len(http_server.requests) == before

    async def test_alias_broken_chain_reported_without_request(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({
            "alias.test": [_cname("alias.test", "gone.test")],
        })
        prober = make_prober()
        hops = await prober.probe(f"http://alias.test:{http_server.port}/")
        assert hops[-1].outcome == "blocked"
        assert "NXDOMAIN" in (hops[-1].reject_reason or "")
        assert hops[-1].connected_peer is None
        assert hops[-1].request_sent is False

    async def test_redirect_after_alias_keeps_per_hop_checks(
        self, fake_dns, http_server, make_prober
    ):
        # 第一跳：别名到本地服务，返回跳转到另一个别名；第二跳独立走完整流程
        fake_dns.set_zones({
            "start-alias.test": [
                _cname("start-alias.test", "start-real.test"),
                _a("start-real.test", "127.0.0.1"),
            ],
            "end-alias.test": [
                _cname("end-alias.test", "end-real.test"),
                _a("end-real.test", "127.0.0.1"),
            ],
        })
        http_server.route(
            "start-alias.test", "/go",
            status=302,
            headers=[("Location",
                      f"http://end-alias.test:{http_server.port}/done")],
        )
        http_server.route("end-alias.test", "/done")
        prober = make_prober()

        hops = await prober.probe(f"http://start-alias.test:{http_server.port}/go")

        assert [h.outcome for h in hops] == ["redirected", "ok"]
        assert hops[0].cname_chain == ["start-alias.test", "start-real.test"]
        assert hops[1].cname_chain == ["end-alias.test", "end-real.test"]
        assert hops[1].status_code == 200

    async def test_https_alias_verified_with_original_hostname(
        self, fake_dns, https_server, make_prober
    ):
        # HTTPS 别名：证书仍按 *原域名* 校验（证书 SAN 含该别名）
        fake_dns.set_zones({
            "https.allowed.demo.test": [_a("https.allowed.demo.test", "127.0.0.1")],
            "alias-https.demo.test": [
                _cname("alias-https.demo.test", "https.allowed.demo.test"),
            ],
        })
        https_server.route("alias-https.demo.test", "/secure")
        prober = make_prober()

        hops = await prober.probe(
            f"https://alias-https.demo.test:{https_server.port}/secure"
        )
        assert hops[-1].outcome == "ok"
        assert hops[-1].tls is not None
        assert "alias-https.demo.test" in hops[-1].tls["san"]
        assert hops[-1].connected_peer.startswith("127.0.0.1:")

    async def test_cidr_denial_distinct_from_ownership_smuggle(
        self, fake_dns, http_server, make_prober
    ):
        # 链尾属主合法但多 A 中含禁区：走 CIDR 全或无，而非“夹带”判定
        fake_dns.set_zones({
            "alias.test": [
                _cname("alias.test", "tip.test"),
                _a("tip.test", "127.0.0.1"),
                _a("tip.test", "8.8.8.8"),
            ],
        })
        prober = make_prober()
        hops = await prober.probe(f"http://alias.test:{http_server.port}/")
        h = hops[-1]
        assert h.outcome == "blocked"
        assert "整体拒绝" in (h.reject_reason or "")
        assert h.foreign_a_records == []
        assert h.resolved_addresses == ["127.0.0.1", "8.8.8.8"]
        assert h.connected_peer is None


# ----------------------------------------------------------- 线协议层测试
class TestCnameWire:
    def test_parse_cname_record(self):
        qid = 42
        pkt = dns_wire.build_response_from_records(
            qid,
            dns_wire.DnsQuestion("alias.test"),
            records=[
                _cname("alias.test", "real.test"),
                _a("real.test", "172.31.10.10"),
            ],
        )
        msg = dns_wire.parse_message(pkt)
        cnames = msg.cname_targets_by_owner()
        assert cnames == {"alias.test": "real.test"}
        assert msg.a_records_by_owner() == {"real.test": ["172.31.10.10"]}
        # 旧属性保持“不区分属主”语义，归属判断交给客户端
        assert msg.a_records == ["172.31.10.10"]

    def test_cname_rdata_truncation_rejected(self):
        import struct

        pkt = bytearray()
        pkt += struct.pack("!HHHHHH", 1, 0x8000, 1, 1, 0, 0)
        pkt += b"\x05alias\x04test\x00"
        pkt += struct.pack("!HH", 1, 1)
        # 属主名 + CNAME 头，RDATA 长度声明 4 但内容截断
        pkt += b"\x05alias\x04test\x00"
        pkt += struct.pack("!HHIH", dns_wire.TYPE_CNAME, 1, 30, 4)
        pkt += b"\x03www"  # 不是完整域名
        with pytest.raises(dns_wire.DnsProtocolError):
            dns_wire.parse_message(bytes(pkt))

"""极简 DNS 线协议（RFC 1035 子集），仅支持 A 记录查询与应答。

探测端只向 *配置指定的解析器* 发 UDP 查询，绝不使用系统 getaddrinfo，
从而保证“先校验、后连接”的地址完全来自可见的 DNS 应答。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

TYPE_A = 1
TYPE_CNAME = 5
CLASS_IN = 1
RCODE_OK = 0
RCODE_NAME_ERROR = 3  # NXDOMAIN
RCODE_SERVFAIL = 2
RCODE_FORMAT_ERROR = 1
RCODE_REFUSED = 5

FLAGS_QR = 0x8000
FLAGS_AA = 0x0400
FLAGS_RD = 0x0100
FLAGS_RA = 0x0080


class DnsProtocolError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.strip(".").split("."):
        if not label:
            continue
        if len(label) > 63:
            raise DnsProtocolError(f"域名标签过长: {label!r}")
        out.append(len(label))
        out.extend(label.encode("ascii"))
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """读取 QNAME，支持压缩指针，返回 (name, 下一偏移)。"""
    labels: list[str] = []
    seen_pointers = 0
    cur = offset
    jumped = False
    next_off = 0
    while True:
        if cur >= len(data):
            raise DnsProtocolError("域名解析越界")
        length = data[cur]
        if length == 0:
            cur += 1
            if not jumped:
                next_off = cur
            break
        if length & 0xC0 == 0xC0:
            if cur + 1 >= len(data):
                raise DnsProtocolError("压缩指针截断")
            ptr = ((length & 0x3F) << 8) | data[cur + 1]
            if not jumped:
                next_off = cur + 2
            cur = ptr
            jumped = True
            seen_pointers += 1
            if seen_pointers > 16:
                raise DnsProtocolError("压缩指针环路")
            continue
        if length & 0xC0:
            raise DnsProtocolError("不支持的标签类型")
        cur += 1
        labels.append(data[cur : cur + length].decode("ascii"))
        cur += length
    return ".".join(labels), (next_off if jumped else cur)


@dataclass
class DnsQuestion:
    qname: str
    qtype: int = TYPE_A
    qclass: int = CLASS_IN


@dataclass
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    # 仅 CNAME 记录使用：解析后的目标域名（线协议解析阶段就解出来，
    # 供别名链追踪；A 记录为 None）
    target: str | None = None


@dataclass
class DnsMessage:
    qid: int
    flags: int
    rcode: int
    questions: list[DnsQuestion]
    answers: list[DnsRecord]

    @property
    def a_records(self) -> list[str]:
        """应答段中全部 class=IN、长度合法的 A 记录地址（不区分属主）。

        注意：这里不做属主过滤；调用方必须结合 ``a_records_by_owner`` /
        ``cname_targets_by_owner`` 做 CNAME 链归属校验，避免把夹带的
        外域名 A 记录用于连接。
        """
        import ipaddress

        out: list[str] = []
        for rec in self.answers:
            if rec.rtype == TYPE_A and rec.rclass == CLASS_IN and len(rec.rdata) == 4:
                out.append(str(ipaddress.ip_address(rec.rdata)))
        return out

    def a_records_by_owner(self) -> dict[str, list[str]]:
        """按属主域名归类 A 记录（属主名一律小写、去尾点）。"""
        import ipaddress

        grouped: dict[str, list[str]] = {}
        for rec in self.answers:
            if rec.rtype == TYPE_A and rec.rclass == CLASS_IN and len(rec.rdata) == 4:
                grouped.setdefault(rec.name.lower().rstrip("."), []).append(
                    str(ipaddress.ip_address(rec.rdata))
                )
        return grouped

    def cname_targets_by_owner(self) -> dict[str, str]:
        """按属主域名返回 CNAME 目标；同一属主出现多条 CNAME 由调用方判错。"""
        return {
            rec.name.lower().rstrip("."): rec.target
            for rec in self.answers
            if rec.rtype == TYPE_CNAME
            and rec.rclass == CLASS_IN
            and rec.target is not None
        }


def build_query(qname: str, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, FLAGS_RD, 1, 0, 0, 0)
    return header + _encode_name(qname) + struct.pack("!HH", TYPE_A, CLASS_IN)


def parse_message(data: bytes, require_qr: bool = True) -> DnsMessage:
    if len(data) < 12:
        raise DnsProtocolError("DNS 报文短于头部")
    qid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if require_qr and not flags & FLAGS_QR:
        raise DnsProtocolError("不是 DNS 应答报文")
    rcode = flags & 0x000F
    offset = 12
    questions: list[DnsQuestion] = []
    for _ in range(qdcount):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            raise DnsProtocolError("问题段截断")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(DnsQuestion(name, qtype, qclass))
    answers: list[DnsRecord] = []
    for _ in range(ancount):
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise DnsProtocolError("应答段截断")
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        if len(rdata) != rdlen:
            raise DnsProtocolError("RDATA 截断")
        target: str | None = None
        if rtype == TYPE_CNAME and rclass == CLASS_IN:
            # CNAME RDATA 是一个完整域名（允许压缩指针）；必须恰好占满 RDATA
            try:
                target, after = _read_name(data, offset)
            except DnsProtocolError as exc:
                raise DnsProtocolError(f"CNAME RDATA 域名解析失败: {exc}") from exc
            if after != offset + rdlen:
                raise DnsProtocolError("CNAME RDATA 长度与域名不一致")
            if not target:
                raise DnsProtocolError("CNAME 目标域名为空")
        offset += rdlen
        answers.append(DnsRecord(name, rtype, rclass, ttl, rdata, target))
    return DnsMessage(qid, flags, rcode, questions, answers)


def build_response(
    qid: int,
    question: DnsQuestion | None,
    rcode: int = RCODE_OK,
    answers: list[str] | None = None,
    ttl: int = 30,
) -> bytes:
    """构造一个仅含 *问题属主自身* A 记录应答的报文（兼容旧调用）。"""
    answers = answers or []
    records = [
        {"type": "A", "name": question.qname if question else "", "value": ip}
        for ip in answers
    ]
    return build_response_from_records(
        qid, question, rcode=rcode, records=records, ttl=ttl
    )


def build_response_from_records(
    qid: int,
    question: DnsQuestion | None,
    rcode: int = RCODE_OK,
    records: list[dict] | None = None,
    ttl: int = 30,
) -> bytes:
    """构造含任意属主 A/CNAME 记录的应答报文（演示解析器与测试使用）。

    每条记录形如：
      {"type": "A",     "name": "owner.example.", "value": "172.31.10.10"}
      {"type": "CNAME", "name": "owner.example.", "value": "target.example."}
    名称按原始 wire 形式编码（不使用压缩指针），探测端必须按属主归类，
    不能把外属主的 A 记录当作问题域名的解析结果。
    """
    import ipaddress

    records = records or []
    ancount = len(records) if rcode == RCODE_OK else 0
    flags = FLAGS_QR | FLAGS_AA | FLAGS_RD | FLAGS_RA | rcode
    out = bytearray(
        struct.pack("!HHHHHH", qid, flags, 1 if question else 0, ancount, 0, 0)
    )
    if question is not None:
        out += _encode_name(question.qname)
        out += struct.pack("!HH", question.qtype, question.qclass)
        for rec in records:
            rtype_str = str(rec.get("type", "")).upper()
            owner = str(rec.get("name", "")).strip()
            value = str(rec.get("value", "")).strip()
            if not owner:
                raise DnsProtocolError("应答记录缺少属主名")
            out += _encode_name(owner)
            if rtype_str == "A":
                addr = ipaddress.ip_address(value)
                if addr.version != 4:
                    raise DnsProtocolError("演示解析器仅支持 A 记录")
                out += struct.pack("!HHIH", TYPE_A, CLASS_IN, ttl, 4)
                out += addr.packed
            elif rtype_str == "CNAME":
                if not value:
                    raise DnsProtocolError("CNAME 记录缺少目标域名")
                target_wire = _encode_name(value)
                out += struct.pack("!HHIH", TYPE_CNAME, CLASS_IN, ttl, len(target_wire))
                out += target_wire
            else:
                raise DnsProtocolError(f"不支持的演示记录类型: {rtype_str!r}")
    return bytes(out)

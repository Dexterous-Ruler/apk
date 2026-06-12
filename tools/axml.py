"""Minimal Android binary-XML (AXML) encoder.

Enough of the format to emit an AndroidManifest.xml that androguard 4 parses
correctly: string pool (UTF-8), resource map for framework attributes,
namespace, and start/end element chunks with typed attributes.

Used only to build our own harmless demo APKs (see build_fake_bank.py). Not a
general-purpose AXML writer — supports exactly the manifest shapes we emit.
"""
from __future__ import annotations

import struct
import zlib  # noqa: F401  (kept for symmetry with dexgen; not used here)

# chunk types
RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_START_ELEM = 0x0102
RES_XML_END_ELEM = 0x0103
RES_XML_RESOURCE_MAP = 0x0180

UTF8_FLAG = 0x00000100

# typed-value data types
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12
TYPE_STRING = 0x03

ANDROID_URI = "http://schemas.android.com/apk/res/android"
NO_ENTRY = 0xFFFFFFFF

# framework attributes we use -> resource id. Order defines their string index
# (0..N-1) and the resource-map order.
FRAMEWORK_ATTRS = [
    ("versionCode", 0x0101021B),
    ("versionName", 0x0101021C),
    ("minSdkVersion", 0x0101020C),
    ("targetSdkVersion", 0x01010270),
    ("name", 0x01010003),
    ("label", 0x01010001),
    ("icon", 0x01010002),
    ("debuggable", 0x0101000F),
    ("exported", 0x01010010),
    ("permission", 0x01010006),
    ("value", 0x01010024),
    ("authorities", 0x01010018),
]
FRAMEWORK_ATTR_IDS = {name: rid for name, rid in FRAMEWORK_ATTRS}


class _Strings:
    """String pool that keeps the framework-attribute names first so the
    resource map lines up with their indices."""

    def __init__(self):
        self._list: list[str] = []
        self._index: dict[str, int] = {}
        for name, _ in FRAMEWORK_ATTRS:
            self.add(name)
        self.n_framework = len(self._list)

    def add(self, s: str) -> int:
        if s not in self._index:
            self._index[s] = len(self._list)
            self._list.append(s)
        return self._index[s]

    def idx(self, s: str) -> int:
        return self._index[s]

    @staticmethod
    def _enc_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        return bytes([(n >> 8) | 0x80, n & 0xFF])

    def build(self) -> bytes:
        data = bytearray()
        offsets = []
        for s in self._list:
            offsets.append(len(data))
            b = s.encode("utf-8")
            data += self._enc_len(len(s))      # char length
            data += self._enc_len(len(b))      # byte length
            data += b
            data += b"\x00"
        while len(data) % 4:
            data += b"\x00"
        header_size = 28
        offsets_size = 4 * len(offsets)
        strings_start = header_size + offsets_size
        total = strings_start + len(data)
        out = bytearray()
        out += struct.pack("<HH", RES_STRING_POOL, header_size)
        out += struct.pack("<I", total)
        out += struct.pack("<I", len(self._list))   # stringCount
        out += struct.pack("<I", 0)                  # styleCount
        out += struct.pack("<I", UTF8_FLAG)          # flags
        out += struct.pack("<I", strings_start)      # stringsStart
        out += struct.pack("<I", 0)                  # stylesStart
        for off in offsets:
            out += struct.pack("<I", off)
        out += data
        return bytes(out)


class Element:
    def __init__(self, tag: str, attrs: list[tuple] | None = None):
        # attrs: list of (android_bool, name, value, kind) where
        # kind in {"str","int","bool"}; android_bool True -> android: ns
        self.tag = tag
        self.attrs = attrs or []
        self.children: list[Element] = []

    def add(self, child: "Element") -> "Element":
        self.children.append(child)
        return child


def _resource_map(strings: _Strings) -> bytes:
    ids = [FRAMEWORK_ATTR_IDS[name] for name, _ in FRAMEWORK_ATTRS]
    size = 8 + 4 * len(ids)
    out = bytearray()
    out += struct.pack("<HH", RES_XML_RESOURCE_MAP, 8)
    out += struct.pack("<I", size)
    for rid in ids:
        out += struct.pack("<I", rid)
    return bytes(out)


def _node_header(chunk_type: int, body_len: int) -> bytes:
    # XML node header: type, headerSize=16, size, lineNumber, comment
    size = 16 + body_len
    return (struct.pack("<HH", chunk_type, 16) + struct.pack("<I", size)
            + struct.pack("<I", 0) + struct.pack("<I", NO_ENTRY))


def _start_ns(strings: _Strings) -> bytes:
    body = struct.pack("<II", strings.idx("android"), strings.idx(ANDROID_URI))
    return _node_header(RES_XML_START_NS, len(body)) + body


def _end_ns(strings: _Strings) -> bytes:
    body = struct.pack("<II", strings.idx("android"), strings.idx(ANDROID_URI))
    return _node_header(RES_XML_END_NS, len(body)) + body


def _start_elem(strings: _Strings, el: Element) -> bytes:
    name_idx = strings.idx(el.tag)
    attr_bytes = bytearray()
    for is_android, name, value, kind in el.attrs:
        ns_idx = strings.idx(ANDROID_URI) if is_android else NO_ENTRY
        nidx = strings.idx(name)
        if kind == "str":
            raw = strings.idx(value)
            dtype = TYPE_STRING
            data = raw
        elif kind == "bool":
            raw = NO_ENTRY
            dtype = TYPE_INT_BOOLEAN
            data = 0xFFFFFFFF if value else 0
        else:  # int
            raw = NO_ENTRY
            dtype = TYPE_INT_DEC
            data = int(value) & 0xFFFFFFFF
        attr_bytes += struct.pack("<II", ns_idx, nidx)
        attr_bytes += struct.pack("<I", raw)
        attr_bytes += struct.pack("<HBBI", 8, 0, dtype, data)  # typed value
    body = bytearray()
    body += struct.pack("<II", NO_ENTRY, name_idx)            # ns, name
    body += struct.pack("<HH", 20, 20)                        # attrStart, size
    body += struct.pack("<HHHH", len(el.attrs), 0, 0, 0)      # count, id/cls/style
    body += attr_bytes
    return _node_header(RES_XML_START_ELEM, len(body)) + bytes(body)


def _end_elem(strings: _Strings, el: Element) -> bytes:
    body = struct.pack("<II", NO_ENTRY, strings.idx(el.tag))
    return _node_header(RES_XML_END_ELEM, len(body)) + body


def _collect_strings(strings: _Strings, el: Element) -> None:
    strings.add(el.tag)
    for is_android, name, value, kind in el.attrs:
        strings.add(name)
        if kind == "str":
            strings.add(value)
    for c in el.children:
        _collect_strings(strings, c)


def _emit(strings: _Strings, el: Element, out: bytearray) -> None:
    out += _start_elem(strings, el)
    for c in el.children:
        _emit(strings, c, out)
    out += _end_elem(strings, el)


def build_axml(root: Element) -> bytes:
    strings = _Strings()
    strings.add("android")
    strings.add(ANDROID_URI)
    _collect_strings(strings, root)

    body = bytearray()
    body += strings.build()
    body += _resource_map(strings)
    body += _start_ns(strings)
    _emit(strings, root, body)
    body += _end_ns(strings)

    out = bytearray()
    out += struct.pack("<HH", RES_XML, 8)
    out += struct.pack("<I", 8 + len(body))
    out += body
    return bytes(out)

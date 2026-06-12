"""Synthesize a minimal, structurally-valid classes.dex.

Goal: produce a dex whose string_ids / type_ids / method_ids tables contain a
chosen set of suspicious class/method references and embedded strings (e.g. an
exfil URL), so our static analyzer's dex pools light up exactly as they would
for a real sample. We do NOT emit code/classes — only the reference tables,
which is all dexparse.py reads. Checksum + SHA-1 signature are computed so the
file is well-formed.

This is for building our own harmless demo APKs only.
"""
from __future__ import annotations

import hashlib
import struct
import zlib

DEX_MAGIC = b"dex\n035\x00"


def _uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_dex(method_refs: list[tuple[str, str]], extra_strings: list[str],
              extra_classes: list[str] | None = None) -> bytes:
    """method_refs: [(dotted_class, method_name)]; extra_classes: dotted class
    names referenced as types only; extra_strings: free strings (URLs, cmds)."""
    extra_classes = extra_classes or []

    def descriptor(dotted: str) -> str:
        return "L" + dotted.replace(".", "/") + ";"

    # collect type descriptors
    type_descs: list[str] = []
    for cls, _ in method_refs:
        type_descs.append(descriptor(cls))
    for cls in extra_classes:
        type_descs.append(descriptor(cls))
    # a return type for the shared proto
    type_descs.append("V")
    type_descs = sorted(set(type_descs))

    # collect strings: every type descriptor + method name + extras + a proto
    # shorty "V"
    method_names = [m for _, m in method_refs]
    all_strings = set(type_descs) | set(method_names) | set(extra_strings)
    all_strings.add("V")
    strings = sorted(all_strings)
    str_index = {s: i for i, s in enumerate(strings)}
    type_index = {t: i for i, t in enumerate(type_descs)}

    # --- string_ids + data ---
    string_data = bytearray()
    string_data_offsets = []
    for s in strings:
        string_data_offsets.append(len(string_data))
        b = s.encode("utf-8")
        string_data += _uleb128(len(s))  # utf16 units (ASCII => len)
        string_data += b
        string_data += b"\x00"

    # --- type_ids ---  (uint string_idx)
    type_ids = b"".join(struct.pack("<I", str_index[t]) for t in type_descs)

    # --- proto_ids --- one proto: shorty "V", return "V", no params
    # proto_id_item: shorty_idx(uint), return_type_idx(uint), params_off(uint)
    proto_ids = struct.pack("<III", str_index["V"], type_index["V"], 0)

    # --- method_ids --- class_idx(ushort), proto_idx(ushort), name_idx(uint)
    method_items = bytearray()
    for cls, meth in method_refs:
        method_items += struct.pack("<HHI", type_index[descriptor(cls)], 0,
                                    str_index[meth])

    # --- lay out sections (header is 0x70 bytes) ---
    off = 0x70
    string_ids_off = off
    off += 4 * len(strings)
    type_ids_off = off
    off += len(type_ids)
    proto_ids_off = off
    off += len(proto_ids)
    field_ids_off = 0  # none
    method_ids_off = off
    off += len(method_items)
    class_defs_off = 0  # none
    data_off = off
    # string data section
    str_data_section_off = off
    abs_string_offsets = [str_data_section_off + o for o in string_data_offsets]
    string_ids = b"".join(struct.pack("<I", o) for o in abs_string_offsets)
    off += len(string_data)
    data_size = len(string_data)
    file_size = off

    # map_off: build a minimal map_list at end
    while off % 4:
        off += 1
    map_off = off

    body = bytearray()
    body += string_ids
    body += type_ids
    body += proto_ids
    body += method_items
    body += string_data
    # pad to map_off
    body += b"\x00" * (map_off - data_off - len(string_ids) - 0)  # recompute below

    # The above padding math is fragile; rebuild deterministically instead.
    body = bytearray()
    body += string_ids
    body += type_ids
    body += proto_ids
    body += method_items
    body += string_data
    # current absolute position = 0x70 + len(body)
    cur = 0x70 + len(body)
    pad = (-cur) % 4
    body += b"\x00" * pad
    map_off = 0x70 + len(body)

    # map_list: uint size, then map_items (type:H, unused:H, size:I, offset:I)
    map_items = [
        (0x0000, 1, 0),                       # HEADER_ITEM
        (0x0001, len(strings), string_ids_off),    # STRING_ID_ITEM
        (0x0002, len(type_descs), type_ids_off),   # TYPE_ID_ITEM
        (0x0003, 1, proto_ids_off),                # PROTO_ID_ITEM
        (0x0005, len(method_refs), method_ids_off),  # METHOD_ID_ITEM
        (0x2002, len(strings), str_data_section_off),  # STRING_DATA_ITEM
        (0x1000, 1, map_off),                      # MAP_LIST
    ]
    map_section = bytearray()
    map_section += struct.pack("<I", len(map_items))
    for t, sz, o in map_items:
        map_section += struct.pack("<HHII", t, 0, sz, o)
    body += map_section
    total = 0x70 + len(body)

    # --- header ---
    header = bytearray(0x70)
    header[0:8] = DEX_MAGIC
    struct.pack_into("<I", header, 0x20, total)               # file_size
    struct.pack_into("<I", header, 0x24, 0x70)                # header_size
    struct.pack_into("<I", header, 0x28, 0x12345678)          # endian_tag
    struct.pack_into("<I", header, 0x2C, 0)                   # link_size
    struct.pack_into("<I", header, 0x30, 0)                   # link_off
    struct.pack_into("<I", header, 0x34, map_off)             # map_off
    struct.pack_into("<I", header, 0x38, len(strings))        # string_ids_size
    struct.pack_into("<I", header, 0x3C, string_ids_off)
    struct.pack_into("<I", header, 0x40, len(type_descs))     # type_ids_size
    struct.pack_into("<I", header, 0x44, type_ids_off)
    struct.pack_into("<I", header, 0x48, 1)                   # proto_ids_size
    struct.pack_into("<I", header, 0x4C, proto_ids_off)
    struct.pack_into("<I", header, 0x50, 0)                   # field_ids_size
    struct.pack_into("<I", header, 0x54, 0)                   # field_ids_off
    struct.pack_into("<I", header, 0x58, len(method_refs))    # method_ids_size
    struct.pack_into("<I", header, 0x5C, method_ids_off)
    struct.pack_into("<I", header, 0x60, 0)                   # class_defs_size
    struct.pack_into("<I", header, 0x64, 0)                   # class_defs_off
    struct.pack_into("<I", header, 0x68, total - data_off)    # data_size
    struct.pack_into("<I", header, 0x6C, data_off)            # data_off

    dex = bytearray(header) + body
    assert len(dex) == total, (len(dex), total)

    # signature = sha1 of everything after the first 32 bytes
    sig = hashlib.sha1(dex[32:]).digest()
    dex[12:32] = sig
    # checksum = adler32 of everything after the first 12 bytes
    checksum = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", dex, 8, checksum)
    return bytes(dex)

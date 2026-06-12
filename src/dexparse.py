"""Minimal, fast DEX table parser.

Reads only the string_ids / type_ids / method_ids tables straight from the
binary — no class/code parsing, no cross-references. This yields everything
the Drebin-style feature matcher needs (full string pool, every referenced
class, every referenced method incl. externals like android.telephony.
SmsManager.sendTextMessage) in well under a second per dex, where a full
androguard DEX() parse takes ~6s each on a large app.

MUTF-8 caveat: we decode with utf-8/replace, which differs from strict MUTF-8
only for embedded NULs and surrogate pairs — irrelevant for identifier and
URL matching.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field


@dataclass
class DexPools:
    """Aggregated lookup pools across all dex files in an APK."""
    strings: set[str] = field(default_factory=set)
    classes: set[str] = field(default_factory=set)        # dotted: java.lang.Class
    class_simple_names: set[str] = field(default_factory=set)  # Class
    method_refs: set[str] = field(default_factory=set)    # dotted: java.lang.Class.getMethod
    method_names: set[str] = field(default_factory=set)   # getMethod
    n_dex: int = 0
    n_strings: int = 0
    n_method_refs: int = 0
    parse_errors: int = 0

    def merge_dex(self, buf: bytes) -> None:
        try:
            parsed = parse_dex(buf)
        except Exception:
            # A hostile/corrupt/packed dex must never abort the whole report;
            # we keep whatever other dex files parsed and flag the failure.
            self.parse_errors += 1
            return
        if parsed is None:
            return
        strings, types, method_refs = parsed
        self.n_dex += 1
        self.n_strings += len(strings)
        self.n_method_refs += len(method_refs)
        self.strings.update(strings)
        for t in types:
            dotted = descriptor_to_dotted(t)
            if dotted:
                self.classes.add(dotted)
                self.class_simple_names.add(dotted.rsplit(".", 1)[-1])
        for cls, name in method_refs:
            dotted = descriptor_to_dotted(cls)
            if dotted:
                self.method_refs.add(f"{dotted}.{name}")
                self.method_names.add(name)


def descriptor_to_dotted(desc: str) -> str | None:
    """'[Ljava/lang/Class;' -> 'java.lang.Class'; primitives -> None."""
    desc = desc.lstrip("[")
    if not desc.startswith("L") or not desc.endswith(";"):
        return None
    return desc[1:-1].replace("/", ".")


# A real dex section count never approaches this; a larger value means the
# size field is corrupt, so we refuse it rather than allocate gigabytes.
_MAX_TABLE = 5_000_000


def _read_uleb128(buf: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    n = len(buf)
    while off < n and shift < 35:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7
    return result, off


def parse_dex(buf: bytes):
    """Return (strings list, type descriptor list, method_ref (class,name) list).

    Returns None if the buffer is not a dex file. Bounds-checked throughout so
    a malformed/packed/truncated secondary dex degrades to a partial pool
    (and merge_dex flags it) instead of raising.
    """
    n = len(buf)
    if n < 0x70 or buf[:3] != b"dex":
        return None
    str_size, str_off = struct.unpack_from("<II", buf, 0x38)
    typ_size, typ_off = struct.unpack_from("<II", buf, 0x40)
    mth_size, mth_off = struct.unpack_from("<II", buf, 0x58)

    def _table_ok(size, off, stride):
        return (0 <= size <= _MAX_TABLE and 0 <= off
                and off + size * stride <= n)

    # string_ids: uint offsets -> uleb128 utf16 length + mutf8 bytes + NUL
    strings: list[str] = []
    if _table_ok(str_size, str_off, 4):
        string_offsets = struct.unpack_from(f"<{str_size}I", buf, str_off)
        find = buf.find
        for so in string_offsets:
            if not (0 <= so < n):
                strings.append("")
                continue
            _, data_start = _read_uleb128(buf, so)
            end = find(b"\x00", data_start)
            if end == -1:
                end = n
            strings.append(buf[data_start:end].decode("utf-8", "replace"))
    n_str = len(strings)

    # type_ids: uint string index
    types: list[str] = []
    if _table_ok(typ_size, typ_off, 4):
        for ti in struct.unpack_from(f"<{typ_size}I", buf, typ_off):
            types.append(strings[ti] if 0 <= ti < n_str else "")
    n_typ = len(types)

    # method_ids: ushort class(type idx), ushort proto, uint name(string idx)
    method_refs: list[tuple[str, str]] = []
    if _table_ok(mth_size, mth_off, 8):
        for i in range(mth_size):
            cls_idx, _proto, name_idx = struct.unpack_from(
                "<HHI", buf, mth_off + i * 8)
            cls = types[cls_idx] if 0 <= cls_idx < n_typ else ""
            nm = strings[name_idx] if 0 <= name_idx < n_str else ""
            if cls and nm:
                method_refs.append((cls, nm))

    return strings, types, method_refs


def pools_from_dex_buffers(buffers) -> DexPools:
    pools = DexPools()
    for buf in buffers:
        pools.merge_dex(buf)
    return pools

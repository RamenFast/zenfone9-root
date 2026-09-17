#!/usr/bin/env python3
"""btf_offsets.py — parse the BTF blob inside a raw arm64 kernel Image and print
struct member byte offsets. Offline, read-only. Needed for the cred-swap root path
(task_struct.tasks / comm / cred / real_cred offsets).

Usage: btf_offsets.py <kernel.Image> <StructName> [member ...]
"""
import struct
import sys

KIND_INT, KIND_PTR, KIND_ARRAY, KIND_STRUCT, KIND_UNION = 1, 2, 3, 4, 5
KIND_ENUM, KIND_FWD, KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST = 6, 7, 8, 9, 10
KIND_RESTRICT, KIND_FUNC, KIND_FUNC_PROTO, KIND_VAR, KIND_DATASEC = 11, 12, 13, 14, 15
KIND_FLOAT, KIND_DECL_TAG, KIND_TYPE_TAG, KIND_ENUM64 = 16, 17, 18, 19

EXTRA = {
    KIND_INT: 4,
    KIND_ARRAY: 12,
    KIND_ENUM: None,        # vlen * 8
    KIND_FUNC_PROTO: None,  # vlen * 8
    KIND_VAR: 4,
    KIND_DATASEC: None,     # vlen * 12
    KIND_DECL_TAG: 4,
    KIND_ENUM64: None,      # vlen * 12
    KIND_STRUCT: None,      # vlen * 12
    KIND_UNION: None,       # vlen * 12
}


def find_btf(data):
    """Locate a plausible BTF header: magic 0xeb9f + sane header/lengths."""
    magic = b"\x9f\xeb"
    start = 0
    while True:
        i = data.find(magic, start)
        if i < 0:
            return None
        start = i + 1
        if i + 24 > len(data):
            continue
        version, flags, hdr_len = data[i + 2], data[i + 3], struct.unpack_from("<I", data, i + 4)[0]
        if version != 1 or hdr_len != 24:
            continue
        type_off, type_len, str_off, str_len = struct.unpack_from("<4I", data, i + 8)
        base = i + hdr_len
        if type_len == 0 or str_len == 0:
            continue
        if base + type_off + type_len > len(data) or base + str_off + str_len > len(data):
            continue
        return base + type_off, type_len, base + str_off, str_len
    return None


def parse(data):
    found = find_btf(data)
    if not found:
        sys.exit("no BTF blob found")
    tstart, tlen, sstart, slen = found
    strtab = data[sstart:sstart + slen]

    def s(off):
        if off == 0 or off >= len(strtab):
            return ""
        end = strtab.find(b"\0", off)
        return strtab[off:end].decode("utf-8", "replace")

    types = {}
    pos, tid = tstart, 1
    end = tstart + tlen
    while pos < end:
        name_off, info, size_type = struct.unpack_from("<3I", data, pos)
        pos += 12
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        kflag = (info >> 31) & 1
        members = []
        if kind in (KIND_STRUCT, KIND_UNION):
            for _ in range(vlen):
                m_name, m_type, m_off = struct.unpack_from("<3I", data, pos)
                pos += 12
                if kflag:
                    bit_off = m_off & 0xFFFFFF
                    bit_sz = (m_off >> 24) & 0xFF
                else:
                    bit_off, bit_sz = m_off, 0
                members.append((s(m_name), bit_off // 8, bit_sz))
        else:
            extra = EXTRA.get(kind, 0)
            if extra is None:
                extra = vlen * (12 if kind in (KIND_DATASEC, KIND_ENUM64) else 8)
            pos += extra
        types[tid] = (kind, s(name_off), size_type, members)
        tid += 1
    return types


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    data = open(sys.argv[1], "rb").read()
    types = parse(data)
    want = sys.argv[2]
    only = set(sys.argv[3:])
    hits = 0
    for tid, (kind, name, size, members) in types.items():
        if name != want or kind not in (KIND_STRUCT, KIND_UNION):
            continue
        hits += 1
        print(f"{name} (id={tid}, size={size} = {hex(size)})")
        for mname, off, bsz in members:
            if only and mname not in only:
                continue
            b = f"  bitfield={bsz}" if bsz else ""
            print(f"   +{hex(off):>8}  {mname}{b}")
    if not hits:
        print(f"struct '{want}' not found")


if __name__ == "__main__":
    main()

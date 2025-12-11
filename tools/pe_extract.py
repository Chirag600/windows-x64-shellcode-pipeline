import struct
import sys
from typing import Tuple


def extract_text_section(pe_bytes: bytes) -> Tuple[bytes, int]:
    if len(pe_bytes) < 0x100:
        raise ValueError("PE file too small")

    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")

    coff_offset = e_lfanew + 4
    (
        machine,
        number_of_sections,
        time_date_stamp,
        ptr_symtab,
        num_symbols,
        size_of_opt,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", pe_bytes, coff_offset)

    opt_offset = coff_offset + 20

    entry_point_rva = struct.unpack_from("<I", pe_bytes, opt_offset + 16)[0]
    print(f"[*] Entry point RVA: 0x{entry_point_rva:x}", file=sys.stderr)

    sect_offset = opt_offset + size_of_opt

    text_section = None
    text_virtual_addr = None
    text_raw_ptr = None
    text_raw_size = None

    for i in range(number_of_sections):
        off = sect_offset + i * 40
        name = pe_bytes[off:off + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
        virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", pe_bytes, off + 8
        )
        if name == ".text":
            text_virtual_addr = virtual_addr
            text_raw_ptr = raw_ptr
            text_raw_size = raw_size

            if raw_ptr + raw_size > len(pe_bytes):
                raise ValueError(".text raw data out of range")

            text_section = pe_bytes[raw_ptr:raw_ptr + raw_size]
            print(
                f"[*] .text section: VirtualAddr=0x{text_virtual_addr:x}, "
                f"RawPtr=0x{text_raw_ptr:x}, RawSize=0x{text_raw_size:x}",
                file=sys.stderr,
            )
            break

    if text_section is None:
        raise ValueError("No .text section found")

    if text_virtual_addr is None or text_raw_size is None:
        raise ValueError("Invalid .text section layout")

    if text_virtual_addr <= entry_point_rva < text_virtual_addr + text_raw_size:
        entry_offset = entry_point_rva - text_virtual_addr
        print(f"[*] Entry point offset in .text: 0x{entry_offset:x}", file=sys.stderr)
    else:
        print(
            f"[!] WARNING: Entry point RVA (0x{entry_point_rva:x}) is outside .text!",
            file=sys.stderr,
        )
        entry_offset = 0

    return text_section, entry_offset

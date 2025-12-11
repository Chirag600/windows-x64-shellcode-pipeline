import sys
from pathlib import Path

from clean_asm import clean_asm_source
from pe_extract import extract_text_section
from encoder import XOR_KEY, build_xor_stub, xor_encode

def print_c_array(shellcode: bytes, varname: str = "shellcode"):
    print("")
    print("/* ================== C SHELLCODE ARRAY ================== */")
    print(f"unsigned char {varname}[] = {{")

    line = "    "
    for i, b in enumerate(shellcode):
        line += f"0x{b:02x}, "
        if (i + 1) % 16 == 0:
            print(line)
            line = "    "
    if line.strip():
        print(line)

    print("};")
    print(f"unsigned int {varname}_len = {len(shellcode)};")
    print("/* ======================================================== */")
    print("")

def do_clean(input_path: Path, output_path: Path) -> None:
    src = input_path.read_text(encoding="utf-8")
    cleaned = clean_asm_source(src)
    output_path.write_text(cleaned, encoding="utf-8")
    print(f"[+] Cleaned assembly written to {output_path}", file=sys.stderr)


def do_extract(input_exe: Path, output_bin: Path) -> None:
    pe_bytes = input_exe.read_bytes()
    text_bytes, entry_offset = extract_text_section(pe_bytes)
    payload = text_bytes[entry_offset:]
    payload = payload.rstrip(b"\x00\x90\xcc")
    print(f"[+] Raw payload length: {len(payload)} bytes", file=sys.stderr)
    encoded = xor_encode(payload, XOR_KEY)
    stub = build_xor_stub(len(encoded), XOR_KEY)
    final_shellcode = stub + encoded

    print(
        f"[+] Final shellcode (stub + encoded payload): {len(final_shellcode)} bytes",
        file=sys.stderr,
    )

    output_bin.write_bytes(final_shellcode)
    print_c_array(final_shellcode, varname="shellcode_64")


def main():
    if len(sys.argv) < 2:
        print("Usage:", file=sys.stderr)
        print("  handle_asm.py clean <input.s> <output.asm>", file=sys.stderr)
        print("  handle_asm.py extract <input.exe> <output.bin>", file=sys.stderr)
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "clean":
        if len(sys.argv) != 4:
            print("Usage: handle_asm.py clean <input.s> <output.asm>", file=sys.stderr)
            sys.exit(1)
        inp = Path(sys.argv[2])
        outp = Path(sys.argv[3])
        do_clean(inp, outp)
        return

    if mode == "extract":
        if len(sys.argv) != 4:
            print("Usage: handle_asm.py extract <input.exe> <output.bin>", file=sys.stderr)
            sys.exit(1)
        exe_path = Path(sys.argv[2])
        bin_path = Path(sys.argv[3])
        do_extract(exe_path, bin_path)
        return

    print(f"Unknown mode: {mode}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()

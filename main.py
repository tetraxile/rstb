#!/usr/bin/env python3

import argparse
import enum
import io
import json
import struct
import sys
import typing
import pyzstd
import binascii


def abort(msg: str):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)

def abort_unless(cond: bool, msg: str):
    if not cond:
        abort(msg)



def read_bytes(data: bytes, offset: int, size: int) -> bytes:
    abort_unless(offset + size <= len(data), f"unexpected EOF (offset: {offset:#x}-{offset+size:#x}, len: {len(data):#x})")
    return data[offset:offset+size]

def read_string(data: bytes, offset: int, size: int = -1, encoding_name: str = "ascii") -> str:
    if size == -1:
        out = b""
        i = 0
        while (char := read_bytes(data, offset+i, 1)) != b'\x00':
            out += char
            i += 1
    else:
        out = read_bytes(data, offset, size)
    
    return out.decode(encoding_name)

def read_signature(data: bytes, offset: int, size: int, expected: str) -> str:
    signature = read_string(data, offset, size)
    abort_unless(signature == expected, f"file signature was {signature}, expected {expected}")
    return signature

def read_u8(data: bytes, offset: int) -> int:
    out = read_bytes(data, offset, 1)
    return int(*struct.unpack("<B", out))

def read_u16(data: bytes, offset: int) -> int:
    out = read_bytes(data, offset, 2)
    return int(*struct.unpack("<H", out))

def read_u32(data: bytes, offset: int) -> int:
    out = read_bytes(data, offset, 4)
    return int(*struct.unpack("<I", out))

def read_u64(data: bytes, offset: int) -> int:
    out = read_bytes(data, offset, 8)
    return int(*struct.unpack("<Q", out))



def write_u8(fp: io.BufferedWriter, value: int):
    fp.write(struct.pack("<B", value))

def write_u16(fp: io.BufferedWriter, value: int):
    fp.write(struct.pack("<H", value))

def write_u32(fp: io.BufferedWriter, value: int):
    fp.write(struct.pack("<I", value))

def write_u64(fp: io.BufferedWriter, value: int):
    fp.write(struct.pack("<Q", value))

def write_bytes(fp: io.BufferedWriter, value: bytes):
    fp.write(value)

def write_string(fp: io.BufferedWriter, value: str, *, max_len: int = -1):
    if max_len > 0:
        value = value[:max_len]
        fp.write("{:\0<{max_len}}".format(value, max_len=max_len).encode("ascii"))
    else:
        fp.write(value.encode("ascii"))

def align(fp: io.BufferedWriter, alignment: int):
    delta = (-fp.tell() % alignment + alignment) % alignment
    fp.seek(delta, io.SEEK_CUR)




def convert_yaml_to_rstb(infile: str, outfile: str, compressed: bool = True):
    print(f"{infile} -> {outfile} (c: {compressed})")

    resources = []
    with open(infile, "r") as f:
        for line in f:
            resource_path, size = line.split(":")
            crc = 0
            try:
                crc = int(resource_path, 16)
            except ValueError:
                crc = binascii.crc32(resource_path.encode("ascii")) & 0xffffffff
            resources.append((crc, int(size)))

    with open(outfile, "wb") as f:
        write_string(f, "RESTBL")    # signature
        write_u32(f, 1)              # version
        write_u32(f, 0xa0)           # path length
        write_u32(f, len(resources)) # crc table length
        write_u32(f, 0)              # path table length

        for resource_path, size in resources:
            write_u32(f, resource_path)
            write_u32(f, size)


def convert_rstb_to_yaml(infile: str, outfile: str, compressed: bool = True):
    print(f"{infile} -> {outfile} (c: {compressed})")

    with open(infile, "rb") as f:
        file_data = f.read()
        if compressed:
            file_data = pyzstd.decompress(file_data)
    
    read_signature(file_data, 0x0, 0x6, "RESTBL")
    version = read_u32(file_data, 0x6)
    abort_unless(version == 1, f"only RSTB version 1 is supported! (got: {version = })")
    path_length = read_u32(file_data, 0xa)
    crc_table_length = read_u32(file_data, 0xe)
    path_table_length = read_u32(file_data, 0x12)

    crc_table_start = 0x16

    outf = open(outfile, "w")

    for i in range(crc_table_length):
        resource_start = crc_table_start + 8 * i
        crc = read_u32(file_data, resource_start)
        size = read_u32(file_data, resource_start + 4)

        outf.write(f"{crc:#010x}: {size}\n")
    
    outf.close()


def main():
    parser = argparse.ArgumentParser(description="generate PFS0 file from directory")
    parser.add_argument("infile")
    parser.add_argument("outfile", nargs="?")
    parser.add_argument("--uncompressed", action="store_true")
    # parser.add_argument("-q", "--quiet", action="store_true")

    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile

    # RSTB.ZS -> YAML
    if infile.endswith(".rsizetable.zs"):
        if outfile is None:
            outfile = infile.removesuffix(".rsizetable.zs") + ".yaml"
        
        convert_rstb_to_yaml(infile, outfile)

    # RSTB -> YAML
    elif infile.endswith(".rsizetable"):
        if outfile is None:
            outfile = infile.removesuffix(".rsizetable") + ".yaml"
        
        convert_rstb_to_yaml(infile, outfile, compressed=False)

    # YAML -> RSTB
    elif infile.endswith(".yaml") and (args.uncompressed or outfile.endswith(".rsizetable")):
        if outfile is None:
            outfile = infile.removesuffix(".yaml") + ".rsizetable"
        
        convert_yaml_to_rstb(infile, outfile, compressed=False)

    # YAML -> RSTB.ZS
    elif infile.endswith(".yaml") and (not args.uncompressed or outfile.endswith(".rsizetable.zs")):
        if outfile is None:
            outfile = infile.removesuffix(".yaml") + ".rsizetable.zs"
        
        convert_yaml_to_rstb(infile, outfile)

    else:
        abort("invalid input file extension (expected one of '.yaml', '.rsizetable', '.rsizetable.zs')")

if __name__ == "__main__":
    main()
"""Minidump (MDMP) format parser.

Parses the binary dump into structured data that the credential extractor
can walk to find LSA secrets, MSV1.0 entries, Kerberos tickets, etc.

Reference: Microsoft MINIDUMP_* structures (dbghelp.h)
"""

import struct
from dataclasses import dataclass, field


MDMP_SIGNATURE = 0x504D444D  # 'MDMP'

# Stream types we care about
STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_MEMORY_LIST = 5
STREAM_MEMORY64_LIST = 9
STREAM_SYSTEM_INFO = 7


@dataclass
class MinidumpHeader:
    signature: int
    version: int
    number_of_streams: int
    stream_directory_rva: int
    checksum: int
    timestamp: int
    flags: int


@dataclass
class StreamDirectory:
    stream_type: int
    data_size: int
    rva: int


@dataclass
class ModuleEntry:
    base_address: int
    size: int
    name: str
    timestamp: int = 0


@dataclass
class MemoryDescriptor64:
    start: int
    size: int


@dataclass
class MemorySegment:
    start: int
    size: int
    data: bytes


@dataclass
class Minidump:
    """Parsed minidump with searchable memory."""

    header: MinidumpHeader
    streams: list[StreamDirectory] = field(default_factory=list)
    modules: list[ModuleEntry] = field(default_factory=list)
    memory: list[MemorySegment] = field(default_factory=list)
    sysinfo_arch: int = 0
    sysinfo_build: int = 0
    sysinfo_major: int = 0
    sysinfo_minor: int = 0

    def read_memory(self, address: int, size: int) -> bytes | None:
        """Read `size` bytes from virtual address `address` in the dump.

        Returns None if the address is not covered by any memory segment.
        """
        for seg in self.memory:
            if seg.start <= address < seg.start + seg.size:
                offset = address - seg.start
                available = seg.size - offset
                if available >= size:
                    return seg.data[offset : offset + size]
                else:
                    # Partial read — try to chain with next segment
                    result = seg.data[offset:]
                    remaining = size - len(result)
                    next_data = self.read_memory(address + len(result), remaining)
                    if next_data:
                        return result + next_data
                    return None
        return None

    def read_u8(self, address: int) -> int | None:
        data = self.read_memory(address, 1)
        return data[0] if data else None

    def read_u16(self, address: int) -> int | None:
        data = self.read_memory(address, 2)
        return struct.unpack_from("<H", data)[0] if data else None

    def read_u32(self, address: int) -> int | None:
        data = self.read_memory(address, 4)
        return struct.unpack_from("<I", data)[0] if data else None

    def read_u64(self, address: int) -> int | None:
        data = self.read_memory(address, 8)
        return struct.unpack_from("<Q", data)[0] if data else None

    def read_ptr(self, address: int) -> int | None:
        """Read a pointer (8 bytes on x64, 4 on x86)."""
        if self.sysinfo_arch == 9:  # AMD64
            return self.read_u64(address)
        else:
            return self.read_u32(address)

    def find_module(self, name: str) -> ModuleEntry | None:
        """Find a module by name (case-insensitive, partial match)."""
        name_lower = name.lower()
        for m in self.modules:
            if name_lower in m.name.lower():
                return m
        return None

    def search_memory(self, pattern: bytes) -> list[int]:
        """Search for a byte pattern across all memory segments.

        Returns list of virtual addresses where the pattern was found.
        """
        results = []
        for seg in self.memory:
            offset = 0
            while True:
                idx = seg.data.find(pattern, offset)
                if idx == -1:
                    break
                results.append(seg.start + idx)
                offset = idx + 1
        return results


def parse(data: bytes) -> Minidump:
    """Parse raw minidump bytes into a Minidump object."""
    if len(data) < 32:
        raise ValueError("Data too small to be a minidump")

    header = _parse_header(data)
    if header.signature != MDMP_SIGNATURE:
        raise ValueError(
            f"Invalid signature: 0x{header.signature:08X} (expected 0x{MDMP_SIGNATURE:08X})"
        )

    dump = Minidump(header=header)

    # Parse stream directory
    offset = header.stream_directory_rva
    for _ in range(header.number_of_streams):
        stype, size, rva = struct.unpack_from("<III", data, offset)
        dump.streams.append(StreamDirectory(stype, size, rva))
        offset += 12

    # Parse each stream
    for stream in dump.streams:
        if stream.stream_type == STREAM_SYSTEM_INFO:
            _parse_system_info(data, stream.rva, dump)
        elif stream.stream_type == STREAM_MODULE_LIST:
            _parse_module_list(data, stream.rva, dump)
        elif stream.stream_type == STREAM_MEMORY_LIST:
            _parse_memory_list(data, stream.rva, dump)
        elif stream.stream_type == STREAM_MEMORY64_LIST:
            _parse_memory64_list(data, stream.rva, dump)

    # If no modules found via stream, discover from PE headers in memory
    if not dump.modules and dump.memory:
        _discover_modules_from_pe(dump)

    return dump


def _parse_header(data: bytes) -> MinidumpHeader:
    sig, version, num_streams, dir_rva, checksum, timestamp = struct.unpack_from(
        "<IIIIII", data, 0
    )
    flags = struct.unpack_from("<Q", data, 24)[0]
    return MinidumpHeader(
        signature=sig,
        version=version & 0xFFFF,
        number_of_streams=num_streams,
        stream_directory_rva=dir_rva,
        checksum=checksum,
        timestamp=timestamp,
        flags=flags,
    )


def _parse_system_info(data: bytes, rva: int, dump: Minidump):
    dump.sysinfo_arch = struct.unpack_from("<H", data, rva)[0]
    dump.sysinfo_major = struct.unpack_from("<I", data, rva + 8)[0]
    dump.sysinfo_minor = struct.unpack_from("<I", data, rva + 12)[0]
    dump.sysinfo_build = struct.unpack_from("<I", data, rva + 16)[0]


def _parse_module_list(data: bytes, rva: int, dump: Minidump):
    count = struct.unpack_from("<I", data, rva)[0]
    offset = rva + 4

    for _ in range(count):
        base = struct.unpack_from("<Q", data, offset)[0]
        size = struct.unpack_from("<I", data, offset + 8)[0]
        timestamp = struct.unpack_from("<I", data, offset + 16)[0]
        name_rva = struct.unpack_from("<I", data, offset + 20)[0]

        name = _read_minidump_string(data, name_rva)

        dump.modules.append(ModuleEntry(
            base_address=base,
            size=size,
            name=name,
            timestamp=timestamp,
        ))

        offset += 108  # sizeof(MINIDUMP_MODULE)


def _parse_memory_list(data: bytes, rva: int, dump: Minidump):
    """Parse MemoryListStream (MINIDUMP_MEMORY_LIST)."""
    count = struct.unpack_from("<I", data, rva)[0]
    offset = rva + 4

    for _ in range(count):
        # MINIDUMP_MEMORY_DESCRIPTOR: StartOfMemoryRange(8) + DataSize(4) + Rva(4)
        start = struct.unpack_from("<Q", data, offset)[0]
        data_size = struct.unpack_from("<I", data, offset + 8)[0]
        data_rva = struct.unpack_from("<I", data, offset + 12)[0]
        offset += 16

        seg_data = data[data_rva : data_rva + data_size]
        dump.memory.append(MemorySegment(start=start, size=data_size, data=seg_data))


def _parse_memory64_list(data: bytes, rva: int, dump: Minidump):
    """Parse Memory64ListStream (MINIDUMP_MEMORY64_LIST) — used for full dumps."""
    num_ranges = struct.unpack_from("<Q", data, rva)[0]
    base_rva = struct.unpack_from("<Q", data, rva + 8)[0]
    offset = rva + 16

    current_rva = int(base_rva)

    for _ in range(int(num_ranges)):
        start = struct.unpack_from("<Q", data, offset)[0]
        size = struct.unpack_from("<Q", data, offset + 8)[0]
        offset += 16

        seg_data = data[current_rva : current_rva + int(size)]
        dump.memory.append(MemorySegment(start=int(start), size=int(size), data=seg_data))
        current_rva += int(size)


def _read_minidump_string(data: bytes, rva: int) -> str:
    """Read a MINIDUMP_STRING (Length + UTF-16LE data)."""
    if rva == 0 or rva >= len(data) - 4:
        return ""
    byte_len = struct.unpack_from("<I", data, rva)[0]
    raw = data[rva + 4 : rva + 4 + byte_len]
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")


def _discover_modules_from_pe(dump: Minidump):
    """Discover modules by scanning memory segments for PE headers (MZ+PE signature).

    Used as fallback when the dump has no ModuleList stream (e.g. custom dumpers).
    """
    for seg in dump.memory:
        if len(seg.data) < 0x200 or seg.data[:2] != b"MZ":
            continue

        pe_off_data = dump.read_memory(seg.start + 0x3C, 4)
        if not pe_off_data:
            continue
        pe_off = struct.unpack_from("<I", pe_off_data)[0]
        pe_sig = dump.read_memory(seg.start + pe_off, 4)
        if not pe_sig or pe_sig != b"PE\x00\x00":
            continue

        opt_off = seg.start + pe_off + 24
        opt_data = dump.read_memory(opt_off, 0x78)
        if not opt_data or len(opt_data) < 0x78:
            continue

        magic = struct.unpack_from("<H", opt_data)[0]
        if magic == 0x20B:  # PE32+
            size_of_image = struct.unpack_from("<I", opt_data, 0x38)[0]
            export_rva = struct.unpack_from("<I", opt_data, 0x70)[0]
        elif magic == 0x10B:  # PE32
            size_of_image = struct.unpack_from("<I", opt_data, 0x38)[0]
            export_rva = struct.unpack_from("<I", opt_data, 0x60)[0]
        else:
            continue

        name = ""
        if export_rva:
            export_dir = dump.read_memory(seg.start + export_rva, 40)
            if export_dir and len(export_dir) >= 16:
                name_rva = struct.unpack_from("<I", export_dir, 12)[0]
                if name_rva:
                    name_data = dump.read_memory(seg.start + name_rva, 128)
                    if name_data:
                        name = name_data.split(b"\x00")[0].decode("ascii", errors="replace")

        dump.modules.append(ModuleEntry(
            base_address=seg.start,
            size=size_of_image,
            name=name,
        ))

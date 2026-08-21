"""Minimal Windows registry hive (REGF) parser.

Parses offline .reg hive files (SAM, SYSTEM, SECURITY) saved via RegSaveKey.
Only implements what's needed: key traversal, value reading.

Reference: https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
"""

import struct


REGF_MAGIC = b"regf"
HBIN_MAGIC = b"hbin"


class RegistryHive:
    """Parse a registry hive file and provide key/value access."""

    def __init__(self, data: bytes):
        if data[:4] != REGF_MAGIC:
            raise ValueError("Not a valid registry hive (missing regf signature)")

        self._data = data
        # Root key offset is at offset 0x24 in the base block (relative to first hbin)
        self._root_offset = struct.unpack_from("<I", data, 0x24)[0]
        self._hbin_start = 0x1000  # hbins start at offset 0x1000

    def open_key(self, path: str):
        """Open a registry key by path (backslash-separated). Returns cell offset."""
        offset = self._root_offset
        if not path:
            return offset

        parts = path.strip("\\").split("\\")
        for part in parts:
            offset = self._find_subkey(offset, part)
            if offset is None:
                raise KeyError(f"Key not found: {path}")
        return offset

    def enum_subkeys(self, key_offset: int) -> list[str]:
        """Enumerate subkey names under a key."""
        cell = self._read_cell(key_offset)
        if cell[0:2] != b"nk":
            return []
        num_subkeys = struct.unpack_from("<I", cell, 0x14)[0]
        if num_subkeys == 0:
            return []
        subkeys_offset = struct.unpack_from("<I", cell, 0x1C)[0]
        return self._enumerate_key_list(subkeys_offset, num_subkeys)

    def enum_values(self, key_offset: int) -> list[str]:
        """Enumerate value names under a key."""
        cell = self._read_cell(key_offset)
        if cell[0:2] != b"nk":
            return []
        num_values = struct.unpack_from("<I", cell, 0x24)[0]
        if num_values == 0:
            return []
        values_offset = struct.unpack_from("<I", cell, 0x28)[0]
        return self._enumerate_value_names(values_offset, num_values)

    def query_value(self, key_offset: int, name: str) -> tuple[int, bytes]:
        """Read a value from a key. Returns (type, data)."""
        cell = self._read_cell(key_offset)
        if cell[0:2] != b"nk":
            raise KeyError(f"Not a key cell")
        num_values = struct.unpack_from("<I", cell, 0x24)[0]
        if num_values == 0:
            raise KeyError(f"Value not found: {name}")
        values_offset = struct.unpack_from("<I", cell, 0x28)[0]
        return self._find_value(values_offset, num_values, name)

    def query_key_class(self, key_offset: int) -> bytes:
        """Read the class name of an NK cell. Returns raw bytes."""
        cell = self._read_cell(key_offset)
        if len(cell) < 0x4C or cell[0:2] != b"nk":
            return b""
        class_len = struct.unpack_from("<H", cell, 0x4A)[0]
        class_offset = struct.unpack_from("<I", cell, 0x30)[0]
        if class_len == 0 or class_offset == 0xFFFFFFFF:
            return b""
        class_cell = self._read_cell(class_offset)
        return class_cell[:class_len]

    def _find_subkey(self, parent_offset: int, name: str) -> int | None:
        """Find a subkey by name under parent."""
        cell = self._read_cell(parent_offset)
        if cell[0:2] != b"nk":
            return None
        num_subkeys = struct.unpack_from("<I", cell, 0x14)[0]
        if num_subkeys == 0:
            return None
        subkeys_offset = struct.unpack_from("<I", cell, 0x1C)[0]
        return self._find_in_key_list(subkeys_offset, num_subkeys, name)

    def _read_cell(self, offset: int) -> bytes:
        """Read a cell at the given offset (relative to hbin data start)."""
        abs_offset = self._hbin_start + offset
        if abs_offset >= len(self._data) - 4:
            return b""
        # Cell size is a signed int32 at the start (negative = allocated)
        size = struct.unpack_from("<i", self._data, abs_offset)[0]
        size = abs(size)
        if size < 4 or abs_offset + size > len(self._data):
            return b""
        return self._data[abs_offset + 4: abs_offset + size]

    def _enumerate_key_list(self, offset: int, count: int) -> list[str]:
        """Parse a subkey list (lf, lh, ri, li) and return names."""
        cell = self._read_cell(offset)
        if len(cell) < 4:
            return []
        sig = cell[0:2]
        num = struct.unpack_from("<H", cell, 2)[0]
        names = []

        if sig in (b"lf", b"lh"):
            # Each entry: offset(4) + hash(4) = 8 bytes
            for i in range(min(num, count)):
                key_off = struct.unpack_from("<I", cell, 4 + i * 8)[0]
                name = self._read_key_name(key_off)
                if name:
                    names.append(name)
        elif sig == b"li":
            # Each entry: just offset(4)
            for i in range(min(num, count)):
                key_off = struct.unpack_from("<I", cell, 4 + i * 4)[0]
                name = self._read_key_name(key_off)
                if name:
                    names.append(name)
        elif sig == b"ri":
            # Index root: points to other lists
            for i in range(min(num, count)):
                sub_off = struct.unpack_from("<I", cell, 4 + i * 4)[0]
                names.extend(self._enumerate_key_list(sub_off, count - len(names)))

        return names

    def _find_in_key_list(self, offset: int, count: int, target: str) -> int | None:
        """Find a key by name in a subkey list."""
        cell = self._read_cell(offset)
        if len(cell) < 4:
            return None
        sig = cell[0:2]
        num = struct.unpack_from("<H", cell, 2)[0]
        target_lower = target.lower()

        if sig in (b"lf", b"lh"):
            for i in range(min(num, count)):
                key_off = struct.unpack_from("<I", cell, 4 + i * 8)[0]
                name = self._read_key_name(key_off)
                if name and name.lower() == target_lower:
                    return key_off
        elif sig == b"li":
            for i in range(min(num, count)):
                key_off = struct.unpack_from("<I", cell, 4 + i * 4)[0]
                name = self._read_key_name(key_off)
                if name and name.lower() == target_lower:
                    return key_off
        elif sig == b"ri":
            for i in range(min(num, count)):
                sub_off = struct.unpack_from("<I", cell, 4 + i * 4)[0]
                result = self._find_in_key_list(sub_off, count, target)
                if result is not None:
                    return result
        return None

    def _read_key_name(self, offset: int) -> str | None:
        """Read the name of an NK cell."""
        cell = self._read_cell(offset)
        if len(cell) < 0x4C or cell[0:2] != b"nk":
            return None
        name_len = struct.unpack_from("<H", cell, 0x48)[0]
        flags = struct.unpack_from("<H", cell, 0x02)[0]
        name_bytes = cell[0x4C: 0x4C + name_len]
        if flags & 0x0020:  # KEY_COMP_NAME — ASCII
            return name_bytes.decode("ascii", errors="replace")
        else:
            return name_bytes.decode("utf-16-le", errors="replace")

    def _enumerate_value_names(self, offset: int, count: int) -> list[str]:
        """Read value names from a value list."""
        cell = self._read_cell(offset)
        names = []
        for i in range(count):
            if 4 + (i + 1) * 4 > len(cell):
                break
            val_off = struct.unpack_from("<I", cell, i * 4)[0]
            name = self._read_value_name(val_off)
            names.append(name)
        return names

    def _find_value(self, list_offset: int, count: int, target: str) -> tuple[int, bytes]:
        """Find and read a value by name."""
        cell = self._read_cell(list_offset)
        target_lower = target.lower()

        for i in range(count):
            if (i + 1) * 4 > len(cell):
                break
            val_off = struct.unpack_from("<I", cell, i * 4)[0]
            name = self._read_value_name(val_off)
            if name.lower() == target_lower:
                return self._read_value_data(val_off)

        raise KeyError(f"Value not found: {target}")

    def _read_value_name(self, offset: int) -> str:
        """Read VK cell name."""
        cell = self._read_cell(offset)
        if len(cell) < 0x18 or cell[0:2] != b"vk":
            return ""
        name_len = struct.unpack_from("<H", cell, 0x02)[0]
        if name_len == 0:
            return "(Default)"
        flags = struct.unpack_from("<H", cell, 0x10)[0]
        name_bytes = cell[0x18: 0x18 + name_len]
        if flags & 0x0001:  # VALUE_COMP_NAME
            return name_bytes.decode("ascii", errors="replace")
        return name_bytes.decode("utf-16-le", errors="replace")

    def _read_value_data(self, offset: int) -> tuple[int, bytes]:
        """Read VK cell data. Returns (type, data)."""
        cell = self._read_cell(offset)
        if len(cell) < 0x18 or cell[0:2] != b"vk":
            return 0, b""
        data_size = struct.unpack_from("<I", cell, 0x04)[0]
        data_offset = struct.unpack_from("<I", cell, 0x08)[0]
        vtype = struct.unpack_from("<I", cell, 0x0C)[0]

        # If high bit of size is set, data is stored inline in the offset field
        if data_size & 0x80000000:
            actual_size = data_size & 0x7FFFFFFF
            return vtype, cell[0x08: 0x08 + actual_size]

        # Otherwise, data is in a separate cell
        data_cell = self._read_cell(data_offset)
        return vtype, data_cell[:data_size]

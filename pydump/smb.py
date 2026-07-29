"""SMB session management — wraps smbprotocol for our specific needs.

Provides:
- NTLM/Kerberos authentication to a remote Windows host
- Named pipe I/O (for DCE/RPC transport)
- File read / write / delete on remote shares
- Process ID discovery via remote registry or WMI
"""

import uuid
from contextlib import contextmanager

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import (
    Open,
    CreateDisposition,
    CreateOptions,
    FileAttributes,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    ShareAccess,
)


class SmbSession:
    """Authenticated SMB2/3 session to a remote Windows host."""

    def __init__(self, target: str, username: str, password: str, domain: str = "."):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain

        self._conn: Connection | None = None
        self._session: Session | None = None
        self._trees: dict[str, TreeConnect] = {}

    def connect(self) -> None:
        conn_id = str(uuid.uuid4())
        self._conn = Connection(conn_id, self.target, port=445)
        self._conn.connect()

        self._session = Session(self._conn, self.username, self.password)
        self._session.connect()

    def disconnect(self) -> None:
        for tree in self._trees.values():
            tree.disconnect()
        self._trees.clear()

        if self._session:
            self._session.disconnect(close=True)
            self._session = None
        if self._conn:
            self._conn.disconnect(close=True)
            self._conn = None

    def tree_connect(self, share: str) -> TreeConnect:
        """Connect to a share (e.g. 'IPC$', 'C$', 'ADMIN$')."""
        unc = f"\\\\{self.target}\\{share}"
        if unc not in self._trees:
            tree = TreeConnect(self._session, unc)
            tree.connect()
            self._trees[unc] = tree
        return self._trees[unc]

    @contextmanager
    def open_pipe(self, pipe_name: str):
        """Open a named pipe on IPC$ for DCE/RPC communication.

        Usage:
            with session.open_pipe("svcctl") as pipe:
                pipe.write(bind_pdu)
                response = pipe.read(4096)
        """
        tree = self.tree_connect("IPC$")

        pipe = Open(tree, pipe_name)
        pipe.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_READ
            | FilePipePrinterAccessMask.GENERIC_WRITE,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        try:
            yield PipeIO(pipe)
        finally:
            pipe.close(get_attributes=False)

    def read_file(self, share: str, path: str) -> bytes:
        """Read an entire file from a remote share."""
        tree = self.tree_connect(share)

        fh = Open(tree, path)
        fh.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_READ,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=ShareAccess.FILE_SHARE_READ,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        )

        try:
            # Read in 64KB chunks
            data = b""
            offset = 0
            while True:
                chunk = fh.read(offset, 65536)
                if not chunk:
                    break
                data += chunk
                offset += len(chunk)
            return data
        finally:
            fh.close(get_attributes=False)

    def delete_file(self, share: str, path: str) -> None:
        """Delete a file on a remote share."""
        tree = self.tree_connect(share)

        fh = Open(tree, path)
        fh.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.DELETE,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=ShareAccess.FILE_SHARE_DELETE,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=CreateOptions.FILE_DELETE_ON_CLOSE
            | CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        fh.close(get_attributes=False)

    def write_file(self, share: str, path: str, data: bytes) -> None:
        """Write data to a file on a remote share (overwrite if exists)."""
        tree = self.tree_connect(share)

        fh = Open(tree, path)
        fh.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_WRITE,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=0,
            create_disposition=CreateDisposition.FILE_OVERWRITE_IF,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        )

        try:
            # Write in 64KB chunks
            offset = 0
            while offset < len(data):
                chunk = data[offset : offset + 65536]
                fh.write(chunk, offset)
                offset += len(chunk)
        finally:
            fh.close(get_attributes=False)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()


class PipeIO:
    """Read/write wrapper for a named pipe SMB handle."""

    def __init__(self, handle: Open):
        self._handle = handle

    def write(self, data: bytes) -> None:
        self._handle.write(data, 0)

    def read(self, length: int = 65536) -> bytes:
        return self._handle.read(0, length)

"""TCP receiver — listens for incoming dump data from the target."""

import socket
import threading


class DumpReceiver:
    """Simple TCP server that receives a single dump payload.

    The target connects back to us and sends the raw MDMP bytes.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self._host = host
        self._port = port
        self._data: bytes = b""
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._done = threading.Event()

    def start(self) -> int:
        """Start listening. Returns the actual port number."""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self._host, self._port))
        self._server.listen(1)
        self._server.settimeout(60)

        # Get actual port (useful when port=0 for auto-assign)
        actual_port = self._server.getsockname()[1]
        self._port = actual_port

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        self._ready.set()

        return actual_port

    def wait(self, timeout: float = 30) -> bytes:
        """Block until data is received or timeout expires."""
        self._done.wait(timeout=timeout)
        return self._data

    def _accept_loop(self):
        """Accept a single connection and read all data."""
        try:
            conn, addr = self._server.accept()
            conn.settimeout(30)

            chunks = []
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)

            self._data = b"".join(chunks)
            conn.close()
        except (socket.timeout, OSError):
            pass
        finally:
            self._done.set()
            if self._server:
                self._server.close()

"""Minimal SMB server for serving the agent binary.

Uses impacket's SMBServer to host the agent.exe on a temporary share
that the target loads via UNC path.
"""

import threading
import os

from impacket.smbserver import SimpleSMBServer


class AgentServer:
    """Serves a single file via SMB for the target to load."""

    def __init__(self, server: SimpleSMBServer):
        self._server = server
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._server.start, daemon=True)
        self._thread.start()

    def stop(self):
        self._server.stop()


def serve_agent(agent_path: str, share_name: str, host: str = "0.0.0.0", port: int = 445) -> AgentServer:
    """Start an SMB server serving the agent binary.

    Args:
        agent_path: Path to agent.exe on the local filesystem
        share_name: SMB share name to use
        host: Listen address
        port: Listen port (445 for standard SMB)

    Returns:
        AgentServer that can be stopped after use
    """
    agent_dir = os.path.dirname(os.path.abspath(agent_path))

    server = SimpleSMBServer(listenAddress=host, listenPort=port)
    server.addShare(share_name, agent_dir)
    server.setSMB2Support(True)

    srv = AgentServer(server)
    srv.start()
    return srv

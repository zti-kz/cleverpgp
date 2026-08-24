from __future__ import annotations

import hashlib
import time

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from cleverpgp.config import app_data_directory


def application_instance_name() -> str:
    identity = str(app_data_directory()).casefold().encode("utf-8")
    suffix = hashlib.sha256(identity).hexdigest()[:20]
    return f"CleverPGP-shell-{suffix}"


def request_primary_shutdown(*, timeout_seconds: float = 15.0) -> int:
    """Ask the regular shell to exit, then wait until it releases its IPC."""

    name = application_instance_name()
    if not _send_command(name, b"shutdown\n"):
        return 0
    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while time.monotonic() < deadline:
        probe = QLocalSocket()
        probe.connectToServer(name)
        if not probe.waitForConnected(100):
            probe.abort()
            return 0
        probe.disconnectFromServer()
        time.sleep(0.05)
    return 1


def _send_command(name: str, command: bytes) -> bool:
    socket = QLocalSocket()
    socket.connectToServer(name)
    if not socket.waitForConnected(250):
        socket.abort()
        return False
    socket.write(command)
    socket.flush()
    socket.waitForBytesWritten(250)
    socket.waitForReadyRead(750)
    socket.readAll()
    socket.disconnectFromServer()
    return True


class SingleApplicationInstance(QObject):
    """Keep one regular Clever PGP shell per Windows user session."""

    activation_requested = Signal()
    shutdown_requested = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.name = application_instance_name()
        self._server = QLocalServer(self)
        self._owns_server = False
        self._server.newConnection.connect(self._accept_connections)

    def acquire(self) -> bool:
        """Return True for the primary shell, otherwise activate it."""

        if self._notify_existing():
            return False
        QLocalServer.removeServer(self.name)
        try:
            self._server.setSocketOptions(
                QLocalServer.SocketOption.UserAccessOption
            )
        except (AttributeError, TypeError):
            pass
        if self._server.listen(self.name):
            self._owns_server = True
            return True
        if self._notify_existing():
            return False
        return False

    def close(self) -> None:
        self._server.close()
        if self._owns_server:
            self._owns_server = False
            QLocalServer.removeServer(self.name)

    def _notify_existing(self) -> bool:
        return _send_command(self.name, b"activate\n")

    def _accept_connections(self) -> None:
        while self._server.hasPendingConnections():
            socket = self._server.nextPendingConnection()
            if socket is None:
                continue
            socket.readyRead.connect(
                lambda connection=socket: self._read_request(connection)
            )
            socket.disconnected.connect(
                lambda connection=socket: self._read_request(connection)
            )
            socket.disconnected.connect(socket.deleteLater)
            if socket.bytesAvailable():
                self._read_request(socket)

    def _read_request(self, socket: QLocalSocket) -> None:
        payload = bytes(socket.readAll())
        if not payload or getattr(socket, "_cleverpgp_handled", False):
            return
        handled = False
        if b"shutdown" in payload:
            handled = True
            self.shutdown_requested.emit()
        elif b"activate" in payload:
            handled = True
            self.activation_requested.emit()
        if handled:
            setattr(socket, "_cleverpgp_handled", True)
            if socket.state() == QLocalSocket.LocalSocketState.ConnectedState:
                socket.write(b"ok\n")
                socket.flush()

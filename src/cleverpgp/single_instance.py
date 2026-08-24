from __future__ import annotations

import hashlib

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from cleverpgp.config import app_data_directory


class SingleApplicationInstance(QObject):
    """Keep one regular Clever PGP shell per Windows user session."""

    activation_requested = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        identity = str(app_data_directory()).casefold().encode("utf-8")
        suffix = hashlib.sha256(identity).hexdigest()[:20]
        self.name = f"CleverPGP-shell-{suffix}"
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
        socket = QLocalSocket()
        socket.connectToServer(self.name)
        if not socket.waitForConnected(250):
            socket.abort()
            return False
        socket.write(b"activate\n")
        socket.flush()
        socket.waitForBytesWritten(250)
        socket.waitForReadyRead(750)
        socket.readAll()
        socket.disconnectFromServer()
        return True

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
        if (
            b"activate" in bytes(socket.readAll())
            and not getattr(socket, "_cleverpgp_activated", False)
        ):
            setattr(socket, "_cleverpgp_activated", True)
            self.activation_requested.emit()
            if socket.state() == QLocalSocket.LocalSocketState.ConnectedState:
                socket.write(b"ok\n")
                socket.flush()

import socket


class ServerConnection:
    """
    Manages the TCP socket connection to the server.
    Implemented as a context manager to ensure sockets are safely opened and closed.
    """

    def __init__(self, host: str, port: int):
        """
        Initializes the connection parameters.

        Args:
            host: The IP address of the server.
            port: The port number of the server.
        """
        self.host = host
        self.port = port
        self.sock = None

    def connect(self) -> None:
        """
        Establishes a TCP connection to the server.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Adding a reasonable timeout so the client doesn't hang forever
        # if the server is unreachable
        self.sock.settimeout(15.0)
        self.sock.connect((self.host, self.port))

    def send_data(self, data: bytes) -> None:
        """
        Sends the entire binary data payload to the server.

        Args:
            data: The bytes representing the packed request.
        """
        if not self.sock:
            raise ConnectionError("Cannot send data: Socket is not connected.")

        self.sock.sendall(data)

    def receive_exact(self, num_bytes: int) -> bytes:
        """
        Receives an exact number of bytes from the server.
        This is crucial for binary protocols to avoid reading partial messages.

        Args:
            num_bytes: The exact number of bytes expected to be read.

        Returns:
            bytes: The received data.

        Raises:
            ConnectionError: If the server closes the connection prematurely.
        """
        if not self.sock:
            raise ConnectionError("Cannot receive data: Socket is not connected.")

        chunks = []
        bytes_received = 0

        while bytes_received < num_bytes:
            # Read up to 4096 bytes at a time, or the remaining required bytes
            chunk = self.sock.recv(min(num_bytes - bytes_received, 4096))

            if chunk == b'':
                raise ConnectionError("Socket connection broken by the server during receive.")

            chunks.append(chunk)
            bytes_received += len(chunk)

        return b''.join(chunks)

    def close(self) -> None:
        """
        Closes the socket connection safely.
        """
        if self.sock:
            self.sock.close()
            self.sock = None

    # --- Context Manager Methods ---

    def __enter__(self):
        """
        Called when entering a 'with' block. Automatically connects to the server.
        """
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Called when exiting a 'with' block. Automatically closes the connection,
        even if an exception was raised inside the block.
        """
        self.close()

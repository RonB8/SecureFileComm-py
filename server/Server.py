from DataBase import DataBase
from RequestHandler import RequestHandler
from RequestParser import *
import socket
import threading
from RequestParser import RequestParser
from Response import Response
from User import UserRepository

# Removed the hardcoded MAX_REQUEST_SIZE as we now read dynamically based on the header
REQUEST_HEADER_SIZE = 23

class Server:
    """
    A class used to manage communication with clients.
    Updated to safely read exact byte streams (Header + Payload) to support robust TCP communication.
    """

    def __init__(self, host: str, port: int) -> None:
        self.host: str = host
        self.port: int = port
        self.user_list = UserRepository()
        self.data_base = DataBase()
        self.request_handler = RequestHandler(self.user_list, self.data_base)

    def start_listening(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}...")

            while True:
                conn, addr = s.accept()
                print(f"Connected to {addr}")

                # Start a new thread for each client
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()

    def _receive_exact(self, conn: socket.socket, num_bytes: int) -> bytes:
        """
        Helper method to receive an exact number of bytes from the socket.
        Crucial for preventing partial reads in TCP streams.
        """
        chunks = []
        bytes_received = 0
        while bytes_received < num_bytes:
            chunk = conn.recv(min(num_bytes - bytes_received, 4096))
            if not chunk:
                return b'' # Connection closed by the client
            chunks.append(chunk)
            bytes_received += len(chunk)
        return b''.join(chunks)

    def handle_client(self, conn: socket.socket, addr: tuple) -> None:
        try:
            # 1. Read exactly 23 bytes for the request header
            header = self._receive_exact(conn, REQUEST_HEADER_SIZE)
            if not header:
                print(f"No data received from {addr}. Closing connection.")
                return

            # 2. Extract payload size from the header (bytes 19 to 23, little-endian)
            payload_size = int.from_bytes(header[19:23], byteorder='little')

            # 3. Read the exact payload dynamically
            payload = self._receive_exact(conn, payload_size)
            if len(payload) != payload_size:
                print(f"Failed to receive full payload from {addr}. Closing.")
                return

            # Reconstruct the full packet for the RequestParser
            packet = header + payload

            # Process the packet
            request = RequestParser(packet)
            response = self.request_handler.handle_request(request)

            if response is None:
                error_response = Response(DEFAULT_VERSION, GENERIC_ERROR, 0, bytearray())
                conn.sendall(error_response.get_packet())  
            else:
                conn.sendall(response)
                print(f"Response sent to {addr}")

        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
            print(f"Connection with {addr} closed.")
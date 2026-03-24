import os


class LocalFileManager:
    """
    Handles all local file operations for the client.
    This includes reading configurations from 'transfer.info',
    managing the user's 'me.info' file, and reading the target file for encryption.
    """

    def __init__(self):
        self.transfer_info_file = 'transfer.info'
        self.me_info_file = 'me.info'

    def read_transfer_info(self) -> tuple:
        """
        Reads the 'transfer.info' file to extract the server's IP and port,
        the client's name, and the path of the file to be sent.

        Returns:
            tuple: (server_ip: str, server_port: int, client_name: str, file_path: str)
        """
        if not os.path.exists(self.transfer_info_file):
            raise FileNotFoundError(f"Missing required configuration file: '{self.transfer_info_file}'")

        with open(self.transfer_info_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines()]

        if len(lines) < 3:
            raise ValueError(f"'{self.transfer_info_file}' is improperly formatted. It must contain at least 3 lines.")

        # Line 1: IP and Port (e.g., "127.0.0.1: 1234" or "127.0.0.1:1234")
        try:
            ip_port_str = lines[0]
            server_ip, server_port_str = ip_port_str.split(':')
            server_ip = server_ip.strip()
            server_port = int(server_port_str.strip())
        except ValueError:
            raise ValueError("Invalid IP:Port format in the first line of 'transfer.info'.")

        # Line 2: Client Name (up to 100 characters according to the assignment)
        client_name = lines[1]
        if len(client_name) > 100:
            raise ValueError("Client name in 'transfer.info' exceeds the 100 character limit.")

        # Line 3: The path to the file that needs to be sent
        file_path = lines[2]

        return server_ip, server_port, client_name, file_path

    def me_info_exists(self) -> bool:
        """
        Checks if the 'me.info' file exists to determine if the user is already registered.
        """
        return os.path.exists(self.me_info_file)

    def write_me_info(self, name: str, client_id_bytes: bytes, private_key_b64: str) -> None:
        """
        Writes the user's registration details to 'me.info'.
        The client ID is stored as a hex string representation of the bytes.

        Args:
            name: The client's name.
            client_id_bytes: The 16-byte UUID returned by the server.
            private_key_b64: The Base64 encoded RSA private key.
        """
        # Convert the 16 bytes of the client ID into a 32-character hex string
        client_id_hex = client_id_bytes.hex()

        with open(self.me_info_file, 'w', encoding='utf-8') as f:
            f.write(f"{name}\n")
            f.write(f"{client_id_hex}\n")
            f.write(f"{private_key_b64}\n")

    def read_me_info(self) -> tuple:
        """
        Reads the user's existing details from 'me.info' for reconnection.

        Returns:
            tuple: (client_name: str, client_id_bytes: bytes, private_key_b64: str)
        """
        if not self.me_info_exists():
            raise FileNotFoundError(f"Cannot read '{self.me_info_file}' because it does not exist.")

        with open(self.me_info_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines()]

        if len(lines) < 3:
            raise ValueError(f"'{self.me_info_file}' is corrupted. It must contain exactly 3 lines.")

        client_name = lines[0]
        client_id_hex = lines[1]
        private_key_b64 = "".join(lines[2:])  # In case the base64 string was split into multiple lines

        # Convert the hex string back to a 16-byte object
        try:
            client_id_bytes = bytes.fromhex(client_id_hex)
        except ValueError:
            raise ValueError("The Client ID in 'me.info' is not a valid hex string.")

        return client_name, client_id_bytes, private_key_b64

    def read_file_to_upload(self, file_path: str) -> bytes:
        """
        Reads the content of the target file in binary mode so it can be encrypted and sent.

        Args:
            file_path: The path of the file as specified in 'transfer.info'.

        Returns:
            bytes: The raw, unencrypted content of the file.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file intended for upload was not found: '{file_path}'")

        try:
            # Read the file in binary mode ('rb') to preserve raw data for encryption
            with open(file_path, 'rb') as file:
                return file.read()
        except PermissionError:
            raise PermissionError(f"Permission denied while trying to read the file: '{file_path}'")

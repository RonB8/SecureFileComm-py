import os
import sys

# Importing the modules we planned in our architecture
from network import ServerConnection
from protocol import RequestBuilder, ResponseParser
from protocol import RES_SUCCESSFUL_REGISTRATION, RES_LOGIN_ACCEPT, RES_PUBLIC_KEY_RECEIVED, RES_VALID_FILE_ACCEPTED
from storage import LocalFileManager
from crypto_manager import CryptoManager
from utils import retry_network, calculate_memcrc


class SecureClientApp:
    """
    The main application class that orchestrates the client's logic and flow.
    """

    def __init__(self):
        self.storage = LocalFileManager()
        self.crypto = CryptoManager()
        self.protocol_builder = RequestBuilder()

        self.server_ip = None
        self.server_port = None
        self.client_name = None
        self.client_id = None
        self.file_path = None

    def run(self):
        """
        The main entry point for the client application flow.
        Reads configuration, decides whether to register or login, and sends the file.
        """
        try:
            print("Starting Secure Client...")

            # Read network and file target info from transfer.info
            self.server_ip, self.server_port, self.client_name, self.file_path = self.storage.read_transfer_info()

            aes_key = None

            # Check if me.info exists to determine the flow (Registration vs. Login)
            if not self.storage.me_info_exists():
                print("First time execution detected. Starting registration flow...")
                self._register_client()
                aes_key = self._send_public_key()
            else:
                print("Existing user detected. Starting login flow...")
                # Load existing user data from me.info
                saved_name, self.client_id, private_key = self.storage.read_me_info()
                self.client_name = saved_name
                self.protocol_builder.update_client_id(self.client_id)
                self.crypto.load_private_key(private_key)

                aes_key = self._login_client()

            # Ensure we have the AES key before proceeding to encrypt and send the file
            if not aes_key:
                print("[FATAL ERROR] Failed to obtain AES key from the server. Exiting.")
                sys.exit(1)

            # Proceed to send the encrypted file
            self._send_file(aes_key)

            print("File transfer completed successfully. Exiting.")

        except Exception as e:
            print(f"[FATAL ERROR] An unexpected error occurred: {e}")
            sys.exit(1)

    @retry_network(max_retries=3)
    def _communicate_with_server(self, request_bytes: bytes) -> tuple:
        """
        A helper method to handle all network communication.
        Connects to the server, sends the request, and receives the response.
        Wrapped with a decorator to automatically retry on network failures.
        Returns: A tuple of (response_code, response_payload)
        """
        with ServerConnection(self.server_ip, self.server_port) as conn:
            conn.send_data(request_bytes)

            # Read exactly 7 bytes for the response header
            header_bytes = conn.receive_exact(7)
            version, code, payload_size = ResponseParser.parse_header(header_bytes)

            # Read the rest of the payload based on the size specified in the header
            payload_bytes = b''
            if payload_size > 0:
                payload_bytes = conn.receive_exact(payload_size)

            return code, payload_bytes

    def _register_client(self):
        """
        Handles the registration flow.
        Sends a registration request and saves the assigned Client ID.
        """
        request_bytes = self.protocol_builder.build_register_request(self.client_name)
        code, payload = self._communicate_with_server(request_bytes)

        if code != RES_SUCCESSFUL_REGISTRATION:
            raise RuntimeError(f"Server rejected registration. Code: {code}")

        # Parse and save the new client ID
        self.client_id = ResponseParser.parse_registration_response(payload)
        self.protocol_builder.update_client_id(self.client_id)

        # Generate new RSA keys and save them
        private_key, _ = self.crypto.generate_rsa_keypair()
        self.storage.write_me_info(self.client_name, self.client_id, private_key)

        print("Registration successful.")

    def _send_public_key(self) -> bytes:
        """
        Sends the generated RSA public key to the server.
        Returns the decrypted AES key provided by the server.
        """
        public_key = self.crypto.get_public_key()
        request_bytes = self.protocol_builder.build_send_public_key_request(self.client_name, public_key)

        code, payload = self._communicate_with_server(request_bytes)

        if code != RES_PUBLIC_KEY_RECEIVED:
            raise RuntimeError(f"Server failed to receive public key. Code: {code}")

        # Extract the encrypted AES key and decrypt it using our private RSA key
        encrypted_aes_key = ResponseParser.parse_public_key_response(payload)
        aes_key = self.crypto.decrypt_rsa(encrypted_aes_key)

        print("Public key sent and AES key received successfully.")
        return aes_key

    def _login_client(self) -> bytes:
        """
        Handles the reconnection/login flow for existing users.
        Returns the decrypted AES key provided by the server.
        """
        request_bytes = self.protocol_builder.build_login_request(self.client_name)
        code, payload = self._communicate_with_server(request_bytes)

        if code != RES_LOGIN_ACCEPT:
            raise RuntimeError(f"Server denied login. Code: {code}")

        # Extract the encrypted AES key and decrypt it using our existing private RSA key
        encrypted_aes_key = ResponseParser.parse_public_key_response(payload)
        aes_key = self.crypto.decrypt_rsa(encrypted_aes_key)

        print("Login successful and AES key received.")
        return aes_key

    def _send_file(self, aes_key: bytes):
        """
        Reads the file, calculates its CRC, encrypts it, and sends it to the server.
        Validates the server's CRC response.
        """
        # Read the raw, unencrypted file
        original_file_data = self.storage.read_file_to_upload(self.file_path)
        orig_file_size = len(original_file_data)
        file_name = os.path.basename(self.file_path)

        # Calculate the CRC of the original file
        file_crc = calculate_memcrc(original_file_data)

        # Encrypt the file data using the AES key
        encrypted_file_data = self.crypto.encrypt_aes(original_file_data, aes_key)

        # Build the send file request
        request_bytes = self.protocol_builder.build_send_file_request(
            file_name=file_name,
            encrypted_content=encrypted_file_data,
            orig_file_size=orig_file_size
        )

        print(f"Sending encrypted file: '{file_name}' ({orig_file_size} bytes)...")
        code, payload = self._communicate_with_server(request_bytes)

        if code != RES_VALID_FILE_ACCEPTED:
            raise RuntimeError(f"Server failed to accept the file. Code: {code}")

        # Extract the CRC checksum calculated by the server
        _, _, server_crc = ResponseParser.parse_file_accepted_response(payload)

        # Validate the CRC
        self._verify_crc(file_name, file_crc, server_crc)

    def _verify_crc(self, file_name: str, client_crc: int, server_crc: int):
        """
        Compares the client's CRC with the server's CRC and notifies the server.
        """
        from protocol import CMD_VALID_CRC, CMD_INVALID_CRC

        if client_crc == server_crc:
            print("CRC match! Sending validation confirmation to the server.")
            request_bytes = self.protocol_builder.build_crc_request(file_name, CMD_VALID_CRC)
            self._communicate_with_server(request_bytes)
        else:
            print(f"CRC mismatch! Client: {client_crc}, Server: {server_crc}. Sending invalid CRC report.")
            request_bytes = self.protocol_builder.build_crc_request(file_name, CMD_INVALID_CRC)
            self._communicate_with_server(request_bytes)
            raise RuntimeError("File transfer failed due to CRC mismatch.")

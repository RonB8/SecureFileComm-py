import struct

# --- Constants ---
# Client Request Codes
CMD_REGISTER = 825
CMD_SEND_PUBLIC_KEY = 826
CMD_LOGIN = 827
CMD_SEND_FILE = 828
CMD_VALID_CRC = 900
CMD_INVALID_CRC = 901
CMD_FOURTH_INVALID_CRC = 902

# Server Response Codes
RES_SUCCESSFUL_REGISTRATION = 1600
RES_FAILED_REGISTRATION = 1601
RES_PUBLIC_KEY_RECEIVED = 1602
RES_VALID_FILE_ACCEPTED = 1603
RES_MESSAGE_RECEIVED = 1604
RES_LOGIN_ACCEPT = 1605
RES_LOGIN_DENIED = 1606
RES_GENERIC_ERROR = 1607

# Sizes
CLIENT_ID_SIZE = 16
NAME_MAX_LENGTH = 255
PUBLIC_KEY_SIZE = 160
HEADER_SIZE = 7  # Server response header size: 1 (Version) + 2 (Code) + 4 (Payload Size)


class RequestBuilder:
    """
    Builds binary request packets to send to the server.
    """

    def __init__(self, client_id: bytes = b'\x00' * CLIENT_ID_SIZE, version: int = 3):
        self.client_id = client_id
        self.version = version

    def update_client_id(self, new_id: bytes):
        """
        Updates the client ID after a successful registration.
        """
        if len(new_id) != CLIENT_ID_SIZE:
            raise ValueError(f"Client ID must be exactly {CLIENT_ID_SIZE} bytes.")
        self.client_id = new_id

    def _build_header(self, code: int, payload_size: int) -> bytes:
        """
        Builds the 23-byte header for client requests.
        Format: ClientID (16 bytes) + Version (1 byte) + Code (2 bytes, LE) + Payload Size (4 bytes, LE)
        """
        return struct.pack(f'<{CLIENT_ID_SIZE}s B H I', self.client_id, self.version, code, payload_size)

    def _pad_string(self, text: str, length: int) -> bytes:
        """
        Encodes a string and pads it with null bytes to the required length.
        """
        encoded = text.encode('utf-8')
        if len(encoded) > length:
            encoded = encoded[:length]
        return encoded.ljust(length, b'\x00')

    def build_register_request(self, name: str) -> bytes:
        """
        Builds a registration request (Code 825).
        """
        payload = self._pad_string(name, NAME_MAX_LENGTH)
        header = self._build_header(CMD_REGISTER, len(payload))
        return header + payload

    def build_login_request(self, name: str) -> bytes:
        """
        Builds a login/reconnect request (Code 827).
        """
        payload = self._pad_string(name, NAME_MAX_LENGTH)
        header = self._build_header(CMD_LOGIN, len(payload))
        return header + payload

    def build_send_public_key_request(self, name: str, public_key: bytes) -> bytes:
        """
        Builds a request to send the generated RSA public key (Code 826).
        """
        if len(public_key) != PUBLIC_KEY_SIZE:
            raise ValueError(f"Public key must be {PUBLIC_KEY_SIZE} bytes.")

        padded_name = self._pad_string(name, NAME_MAX_LENGTH)
        payload = padded_name + public_key
        header = self._build_header(CMD_SEND_PUBLIC_KEY, len(payload))
        return header + payload

    def build_send_file_request(self, file_name: str, encrypted_content: bytes, orig_file_size: int,
                                packet_num: int = 1, total_packets: int = 1) -> bytes:
        """
        Builds a request to upload an encrypted file (Code 828).
        """
        content_size = len(encrypted_content)
        padded_name = self._pad_string(file_name, NAME_MAX_LENGTH)

        # Payload format: Content Size (4), Orig Size (4), Packet Num (2), Total Packets (2), File Name (255), Content
        payload_meta = struct.pack('<I I H H 255s', content_size, orig_file_size, packet_num, total_packets,
                                   padded_name)
        payload = payload_meta + encrypted_content

        header = self._build_header(CMD_SEND_FILE, len(payload))
        return header + payload

    def build_crc_request(self, file_name: str, crc_status_code: int) -> bytes:
        """
        Builds a CRC validation report request (Codes 900, 901, or 902).
        """
        if crc_status_code not in (CMD_VALID_CRC, CMD_INVALID_CRC, CMD_FOURTH_INVALID_CRC):
            raise ValueError("Invalid CRC status code.")

        payload = self._pad_string(file_name, NAME_MAX_LENGTH)
        header = self._build_header(crc_status_code, len(payload))
        return header + payload


class ResponseParser:
    """
    Parses binary response packets received from the server.
    """

    @staticmethod
    def parse_header(header_bytes: bytes) -> tuple:
        """
        Parses the 7-byte server response header.
        Returns: (version, code, payload_size)
        """
        if len(header_bytes) < HEADER_SIZE:
            raise ValueError("Incomplete header received from server.")

        # Format: Version (1 byte), Code (2 bytes, LE), Payload Size (4 bytes, LE)
        version, code, payload_size = struct.unpack('<B H I', header_bytes)
        return version, code, payload_size

    @staticmethod
    def parse_registration_response(payload: bytes) -> bytes:
        """
        Extracts the Client ID from a successful registration response.
        """
        if len(payload) < CLIENT_ID_SIZE:
            raise ValueError("Payload too short to contain a Client ID.")
        return payload[:CLIENT_ID_SIZE]

    @staticmethod
    def parse_public_key_response(payload: bytes) -> bytes:
        """
        Extracts the encrypted AES key from the server's response.
        The payload starts with the Client ID (16 bytes), followed by the AES key.
        """
        if len(payload) <= CLIENT_ID_SIZE:
            raise ValueError("Payload does not contain the AES key.")
        return payload[CLIENT_ID_SIZE:]

    @staticmethod
    def parse_file_accepted_response(payload: bytes) -> tuple:
        """
        Extracts metadata from the file acceptance response (Code 1603).
        Returns: (content_size, file_name, crc_checksum)
        """
        # Minimum size: Client ID (16) + Content Size (4) + Name (255) + CRC (4) = 279 bytes
        min_expected_size = CLIENT_ID_SIZE + 4 + NAME_MAX_LENGTH + 4
        if len(payload) < min_expected_size:
            raise ValueError("Payload too short for a file acceptance response.")

        offset = CLIENT_ID_SIZE
        content_size = struct.unpack('<I', payload[offset:offset + 4])[0]
        offset += 4

        raw_name = payload[offset:offset + NAME_MAX_LENGTH]
        file_name = raw_name.replace(b'\x00', b'').decode('utf-8')
        offset += NAME_MAX_LENGTH

        crc_checksum = struct.unpack('<I', payload[offset:offset + 4])[0]

        return content_size, file_name, crc_checksum
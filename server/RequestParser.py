
# Constants for default version and payload size
DEFAULT_VERSION = 3
DEFAULT_PAYLOAD_SIZE = 300

# Command codes
REGISTRY = 825
SEND_PUBLIC_KEY = 826
LOGIN = 827
SEND_FILE = 828
VALID_CRC = 900
INVALID_CRC = 901
FOURTH_INVALID_CRC = 902

# Status codes
SUCCESSFUL_REGISTRATION = 1600
FAILED_REGISTRATION = 1601
PUBLIC_KEY_RECEIVED = 1602
VALID_FILE_ACCEPTED = 1603
MESSAGE_RECEIVED = 1604
LOGIN_ACCEPT = 1605
LOGIN_DENIED = 1606
GENERIC_ERROR = 1607

# Request header and field size constants
REQUEST_HEADER_SIZE = 23
NAME_MAX_LENGTH = 255
PUBLIC_KEY_SIZE = 160
FILE_TRANSFER_PAYLOAD_SIZE = 267

class RequestParser:
    """
    A class to parse incoming request packets from clients.

    Properties:
        client_ID (bytes): The unique identifier for the client.
        version (int): The version of the request protocol being used.
        code (int): The command code indicating the type of request.
        payload_size (int): The size of the payload in bytes.
        payload (bytes): The actual data sent by the client.

    Methods:
        get_name(): Returns the name associated with the request if applicable.
        get_public_key(): Returns the public key sent by the client if applicable.
        get_content_size(): Returns the size of the content of the file being sent.
        get_orig_file_size(): Returns the size of the file without encryption.

    Preliminary explanation of the get_packet_number and total_packets methods:
        Each request can send a file up to a certain predefined size.
        If the client wants to send a larger file, he divides it into packets, and each packet is marked with a number.
        get_packet_number(): Returns the number of current packet.
        total_packets(): Returns the number of packets that the file is divided into.

        file_name(): Returns the name of the file being sent.
        get_file_content(): Returns the actual content of the file being sent (encrypted).
    """

    def __init__(self, packet: bytes) -> None:
        # Checking there are enough bytes for the basic fields of the request.
        if len(packet) < REQUEST_HEADER_SIZE:
            raise ValueError(f"Packet size must be at least {REQUEST_HEADER_SIZE} bytes")

        # Parse packet fields
        self.client_ID = packet[:16]
        self.version = int.from_bytes(packet[16:17], byteorder='little')
        self.code = int.from_bytes(packet[17:19], byteorder='little')
        self.payload_size = int.from_bytes(packet[19:23], byteorder='little')
        self.payload = packet[23:]

        # Validate payload_size based on request type
        if self.code in {REGISTRY, LOGIN, VALID_CRC, INVALID_CRC, FOURTH_INVALID_CRC}:
            if self.payload_size != NAME_MAX_LENGTH:
                raise ValueError(f"Payload size must be {NAME_MAX_LENGTH} for request code {self.code}")
        elif self.code == SEND_PUBLIC_KEY:
            if self.payload_size != PUBLIC_KEY_SIZE + NAME_MAX_LENGTH:
                raise ValueError(f"Payload size must be {PUBLIC_KEY_SIZE} for request code: {SEND_PUBLIC_KEY}")
        elif self.code == SEND_FILE:
            if self.payload_size < FILE_TRANSFER_PAYLOAD_SIZE:
                raise ValueError(f"Payload size must be at least {FILE_TRANSFER_PAYLOAD_SIZE} for SEND_FILE")
        else:
            # Raise an exception for unknown code values
            raise ValueError(f"Unknown request code: {self.code}")



    def get_name(self) -> str:
        if self.code not in(REGISTRY, SEND_PUBLIC_KEY, LOGIN):
            raise Exception(f'There is no name field to request code: {self.code}')

        name = self.payload[:256].decode()
        return name.replace('\0', '')

    def get_public_key(self) -> bytes:
        if self.code != SEND_PUBLIC_KEY:
            raise Exception(f'There is no public key field to request code: {self.code}')

        return self.payload[255: 415]

    def get_content_size(self) -> int:
        if self.code != SEND_FILE:
            raise Exception(f'There is no file fields to request code: {self.code}')

        return int.from_bytes(self.payload[:4], byteorder='little')

    def get_orig_file_size(self) -> int:
        if self.code != SEND_FILE:
            raise Exception(f'There is no file fields to request code: {self.code}')

        return int.from_bytes(self.payload[4: 8], byteorder='little')

    def get_packet_number(self) -> int:
        if self.code != SEND_FILE:
            raise Exception(f'There is no file fields to request code: {self.code}')

        return int.from_bytes(self.payload[8: 10], byteorder='little')

    def total_packets(self) -> int:
        if self.code != SEND_FILE:
            raise Exception(f'There is no file fields to request code: {self.code}')

        return int.from_bytes(self.payload[10: 12], byteorder='little')

    def file_name(self) -> str:
        if self.code not in (SEND_FILE, VALID_CRC, INVALID_CRC, FOURTH_INVALID_CRC):
            raise Exception(f'There is no file fields to request code: {self.code}')

        if self.code == SEND_FILE:
            res = self.payload[12: 267].decode()

        else:
            res = self.payload[: 255].decode()

        return res.replace('\0', '')

    def get_file_content(self) -> bytes:
        if self.code != SEND_FILE:
            raise Exception(f'There is no file fields to request code: {self.code}')

        content_size = self.get_content_size()
        start_content = 267
        end_content = start_content + content_size

        return self.payload[start_content: end_content]


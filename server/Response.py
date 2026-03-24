import struct

class Response:
    """
    A class to create a response packet to be sent to clients.

    Attributes:
        packet (bytearray): The response packet containing version, code, payload size, and payload.

    Methods:
        get_packet() -> bytearray: Returns the complete response packet.
    """

    def __init__(self, version: int, code: int, payload_size: int, payload: bytes) -> None:
        """
        Initializes a Response object and constructs the packet.

        Args:
            version (int): The version of the response protocol.
            code (int): The command code for the response.
            payload_size (int): The size of the payload in bytes.
            payload (bytes): The actual data being sent as the response.
        """
        self.packet = bytearray()

        # Adding the version
        self.packet += struct.pack('B', version)  # 'B' for unsigned 8-bit integer

        # Adding the code
        self.packet += struct.pack('<H', code)  # '<H' for little-endian 16-bit unsigned integer

        # Adding the payload size
        self.packet += struct.pack('<I', payload_size)  # '<I' for little-endian 32-bit unsigned integer

        # Adding the payload
        self.packet += payload

    def get_packet(self) -> bytearray:
        """
        Returns the complete response packet.

        Returns:
            bytearray: The constructed response packet.
        """
        return self.packet


class Payload:
    """
    A class to create a payload for the response.

    Attributes:
        packet (bytearray): The payload packet containing client ID, encrypted AES key, content size, file name, and checksum.

    Methods:
        __init__(c_id: bytearray, encrypted_aes_key: bytes=None, content_size: int=None, file_name: str=None, cksum: int=None) -> None: Initializes the Payload object and constructs the packet.
    """

    def __init__(self, c_id: bytearray, encrypted_aes_key: bytes=None, content_size: int=None, file_name: str=None, cksum: int=None) -> None:
        """
        Initializes a Payload object and constructs the payload packet.

        Args:
            c_id (bytearray): The client ID.
            encrypted_aes_key (bytes, optional): The encrypted AES key, if provided.
            content_size (int, optional): The size of the content, if provided.
            file_name (str, optional): The name of the file, if provided.
            cksum (int, optional): The checksum value, if provided.
        """
        self.packet = bytearray([])

        self.packet += c_id

        if encrypted_aes_key is not None:
            self.packet += encrypted_aes_key

        if content_size is not None:
            self.packet += struct.pack('<I', content_size)  # '<I' for little-endian 32-bit unsigned integer

        if file_name is not None:
            padded_file_name = padding(file_name, 255)

            for c in padded_file_name:
                self.packet.append(ord(c))

        if cksum is not None:
            self.packet += struct.pack('<I', cksum)  # '<I' for little-endian 32-bit unsigned integer


def padding(original_string: str, target_len: int) -> str:
    """
    Pads the original string with null characters to meet the target length.

    Args:
        original_string (str): The string to be padded.
        target_len (int): The target length for the padded string.

    Returns:
        str: The padded string.
    """
    current_length = len(original_string)

    if current_length <= target_len:
        zeros_to_add = target_len - current_length
        padded_string = '\0' * zeros_to_add + original_string
    else:
        padded_string = original_string

    return padded_string

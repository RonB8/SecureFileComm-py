import unittest
import struct

# Importing the classes and constants from our protocol module
from protocol import RequestBuilder, ResponseParser
from protocol import (
    CMD_REGISTER, CMD_SEND_PUBLIC_KEY, CMD_SEND_FILE,
    CLIENT_ID_SIZE, NAME_MAX_LENGTH, PUBLIC_KEY_SIZE
)


class TestRequestBuilder(unittest.TestCase):
    """
    Test suite for the RequestBuilder class.
    """

    def setUp(self):
        """
        Set up a RequestBuilder instance with a dummy client ID for testing.
        """
        self.dummy_client_id = b'A' * CLIENT_ID_SIZE
        self.builder = RequestBuilder(client_id=self.dummy_client_id, version=3)

    def test_pad_string_short(self):
        """
        Test that a short string is properly padded with null bytes.
        """
        result = self.builder._pad_string("test", 10)
        expected = b'test\x00\x00\x00\x00\x00\x00'
        self.assertEqual(result, expected)

    def test_pad_string_long(self):
        """
        Test that a string longer than the requested length is truncated.
        """
        result = self.builder._pad_string("this_is_too_long", 10)
        expected = b'this_is_to'
        self.assertEqual(result, expected)

    def test_build_register_request(self):
        """
        Test the creation of a registration request packet.
        """
        name = "Alice"
        request = self.builder.build_register_request(name)

        # Header size is 23, name payload is 255. Total should be 278.
        self.assertEqual(len(request), 23 + NAME_MAX_LENGTH)

        # Unpack the header to verify its fields
        client_id, version, code, payload_size = struct.unpack('<16s B H I', request[:23])

        self.assertEqual(client_id, self.dummy_client_id)
        self.assertEqual(version, 3)
        self.assertEqual(code, CMD_REGISTER)
        self.assertEqual(payload_size, NAME_MAX_LENGTH)

    def test_build_send_public_key_request_valid(self):
        """
        Test sending a public key with the correct size.
        """
        dummy_pub_key = b'K' * PUBLIC_KEY_SIZE
        request = self.builder.build_send_public_key_request("Alice", dummy_pub_key)

        expected_payload_size = NAME_MAX_LENGTH + PUBLIC_KEY_SIZE
        self.assertEqual(len(request), 23 + expected_payload_size)

        _, _, code, payload_size = struct.unpack('<16s B H I', request[:23])
        self.assertEqual(code, CMD_SEND_PUBLIC_KEY)
        self.assertEqual(payload_size, expected_payload_size)

    def test_build_send_public_key_request_invalid_size(self):
        """
        Test that providing an invalid public key size raises a ValueError.
        """
        invalid_pub_key = b'K' * 50  # Not 160 bytes
        with self.assertRaises(ValueError):
            self.builder.build_send_public_key_request("Alice", invalid_pub_key)


class TestResponseParser(unittest.TestCase):
    """
    Test suite for the ResponseParser class.
    """

    def test_parse_header_valid(self):
        """
        Test parsing a valid 7-byte server response header.
        """
        # Pack: Version=3, Code=1600 (Success), PayloadSize=16
        header_bytes = struct.pack('<B H I', 3, 1600, 16)
        version, code, payload_size = ResponseParser.parse_header(header_bytes)

        self.assertEqual(version, 3)
        self.assertEqual(code, 1600)
        self.assertEqual(payload_size, 16)

    def test_parse_header_too_short(self):
        """
        Test that parsing a header smaller than 7 bytes raises a ValueError.
        """
        short_header = b'\x03\x40\x06'  # Only 3 bytes
        with self.assertRaises(ValueError):
            ResponseParser.parse_header(short_header)

    def test_parse_registration_response(self):
        """
        Test extracting the client ID from a registration response.
        """
        expected_client_id = b'B' * CLIENT_ID_SIZE
        payload = expected_client_id + b'some_extra_ignored_bytes'

        result = ResponseParser.parse_registration_response(payload)
        self.assertEqual(result, expected_client_id)

    def test_parse_file_accepted_response(self):
        """
        Test extracting metadata from a file acceptance response.
        """
        client_id = b'C' * CLIENT_ID_SIZE
        content_size = 1024
        file_name = "test_doc.txt"
        crc_checksum = 987654321

        # Build the mock payload exactly as the server would send it
        padded_name = file_name.encode('utf-8').ljust(NAME_MAX_LENGTH, b'\x00')
        payload = client_id + struct.pack('<I', content_size) + padded_name + struct.pack('<I', crc_checksum)

        parsed_size, parsed_name, parsed_crc = ResponseParser.parse_file_accepted_response(payload)

        self.assertEqual(parsed_size, content_size)
        self.assertEqual(parsed_name, file_name)  # Ensure null bytes were stripped
        self.assertEqual(parsed_crc, crc_checksum)


if __name__ == '__main__':
    unittest.main()
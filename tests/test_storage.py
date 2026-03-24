import unittest
from unittest.mock import patch, mock_open
import os

# Importing the LocalFileManager class
from storage import LocalFileManager


class TestLocalFileManager(unittest.TestCase):
    """
    Test suite for the LocalFileManager class.
    Uses mocking to simulate file reading and writing without touching the actual disk.
    """

    def setUp(self):
        """
        Initialize the LocalFileManager instance before each test.
        """
        self.storage = LocalFileManager()

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="127.0.0.1: 1234\nTestUser\nC:\\dummy\\path.txt\n")
    def test_read_transfer_info_valid(self, mock_file, mock_exists):
        """
        Test reading a correctly formatted 'transfer.info' file.
        """
        mock_exists.return_value = True
        ip, port, name, path = self.storage.read_transfer_info()

        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(port, 1234)
        self.assertEqual(name, "TestUser")
        self.assertEqual(path, "C:\\dummy\\path.txt")

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data="127.0.0.1:1234\nTooLongName" + "A" * 100 + "\npath.txt")
    def test_read_transfer_info_name_too_long(self, mock_file, mock_exists):
        """
        Test that a ValueError is raised if the client name exceeds 100 characters.
        """
        mock_exists.return_value = True
        with self.assertRaises(ValueError):
            self.storage.read_transfer_info()

    @patch('builtins.open', new_callable=mock_open)
    def test_write_me_info(self, mock_file):
        """
        Test writing user details to 'me.info'. Ensures UUID is converted to hex.
        """
        dummy_uuid = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16'
        dummy_b64_key = "dummyBase64KeyString"

        self.storage.write_me_info("TestUser", dummy_uuid, dummy_b64_key)

        # Check that the file was opened in write mode
        mock_file.assert_called_with('me.info', 'w', encoding='utf-8')

        # Get all the text that was written to the file
        handle = mock_file()
        written_content = "".join(call.args[0] for call in handle.write.call_args_list)

        self.assertIn("TestUser\n", written_content)
        self.assertIn(f"{dummy_uuid.hex()}\n", written_content)
        self.assertIn(f"{dummy_b64_key}\n", written_content)

    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open,
           read_data="TestUser\n01020304050607080910111213141516\ndummyBase64KeyString\n")
    def test_read_me_info_valid(self, mock_file, mock_exists):
        """
        Test reading a correctly formatted 'me.info' file.
        """
        mock_exists.return_value = True
        name, uuid_bytes, b64_key = self.storage.read_me_info()

        self.assertEqual(name, "TestUser")
        self.assertEqual(uuid_bytes, bytes.fromhex("01020304050607080910111213141516"))
        self.assertEqual(b64_key, "dummyBase64KeyString")


if __name__ == '__main__':
    unittest.main()
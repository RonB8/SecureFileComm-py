import unittest

# Importing the CRC function from utils
from utils import calculate_memcrc


class TestUtils(unittest.TestCase):
    """
    Test suite for the utility functions.
    """

    def test_calculate_memcrc_empty(self):
        """
        Test that the CRC calculation handles an empty byte string correctly.
        """
        result = calculate_memcrc(b"")
        self.assertIsInstance(result, int)
        self.assertEqual(result, 4294967295)  # Expected ~0 result for empty input in POSIX cksum

    def test_calculate_memcrc_basic_string(self):
        """
        Test that the CRC calculation returns a consistent integer for a known string.
        """
        data = b"Hello World"
        result = calculate_memcrc(data)

        self.assertIsInstance(result, int)
        # Verify that running it twice on the same data yields the exact same CRC
        self.assertEqual(result, calculate_memcrc(data))


if __name__ == '__main__':
    unittest.main()
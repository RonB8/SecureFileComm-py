import unittest
import base64
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

# Importing the CryptoManager class
from client.crypto_manager import CryptoManager


class TestCryptoManager(unittest.TestCase):
    """
    Test suite for the CryptoManager class.
    Updated to ensure strict compatibility with the server's 160-byte public key requirement
    and the X.509 header manipulation implemented on both client and server sides.
    """

    def setUp(self):
        """
        Initialize a fresh CryptoManager instance before each test.
        """
        self.crypto = CryptoManager()

    def test_generate_rsa_keypair(self):
        """
        Test that generating an RSA keypair returns the correct types
        and that the public key payload is exactly 160 bytes.
        """
        priv_b64, pub_bytes = self.crypto.generate_rsa_keypair()

        self.assertIsInstance(priv_b64, str)
        self.assertIsInstance(pub_bytes, bytes)
        self.assertEqual(len(pub_bytes), 160)
        self.assertIsNotNone(self.crypto.private_key)

    def test_server_compatibility_with_public_key(self):
        """
        Test that the server can successfully reconstruct the RSA public key
        by prepending the X.509 header to the first 140 bytes of our payload.
        This explicitly tests the 'Option 2' implementation.
        """
        self.crypto.generate_rsa_keypair()
        pub_payload = self.crypto.get_public_key()

        # The exact header the server uses to reconstruct the key
        X509_HEADER = b'0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x00'

        # Simulate server logic: combine header with the first 140 bytes of the payload
        reconstructed_key_bytes = X509_HEADER + pub_payload[:140]

        try:
            # If this fails, the key is corrupted or the slicing logic is wrong
            server_side_key = RSA.import_key(reconstructed_key_bytes)

            # Verify that the reconstructed key matches the original mathematical properties
            self.assertEqual(server_side_key.n, self.crypto.private_key.n)
            self.assertEqual(server_side_key.e, self.crypto.private_key.e)
        except Exception as e:
            self.fail(f"Server-side key reconstruction failed: {e}")

    def test_decrypt_rsa(self):
        """
        Test that the client manager can correctly decrypt an AES key
        encrypted by the server using the reconstructed public key.
        """
        self.crypto.generate_rsa_keypair()
        pub_payload = self.crypto.get_public_key()
        dummy_aes_key = b'A' * 32  # 256-bit dummy key

        # Simulate server encryption logic
        X509_HEADER = b'0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x00'
        server_side_key = RSA.import_key(X509_HEADER + pub_payload[:140])
        cipher_rsa = PKCS1_OAEP.new(server_side_key)
        encrypted_aes = cipher_rsa.encrypt(dummy_aes_key)

        # Test the client decryption method
        decrypted_aes = self.crypto.decrypt_rsa(encrypted_aes)
        self.assertEqual(decrypted_aes, dummy_aes_key)

    def test_encrypt_aes(self):
        """
        Test that AES encryption produces valid ciphertext (CBC mode, 0 IV, PKCS7 padding)
        that can be decrypted back to the original data.
        """
        dummy_aes_key = b'B' * 32
        original_data = b"Hello, this is a secret file content meant for testing."

        # Encrypt using the manager
        encrypted_data = self.crypto.encrypt_aes(original_data, dummy_aes_key)

        # Check basic properties of the ciphertext
        self.assertTrue(len(encrypted_data) > len(original_data))
        self.assertEqual(len(encrypted_data) % AES.block_size, 0)

        # Manually decrypt it to verify the contents and padding
        iv = b'\x00' * 16
        cipher_aes = AES.new(dummy_aes_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher_aes.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, AES.block_size)

        self.assertEqual(decrypted_data, original_data)


if __name__ == '__main__':
    unittest.main()
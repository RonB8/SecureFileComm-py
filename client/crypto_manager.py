import base64
import Crypto.PublicKey.RSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad

class CryptoManager:
    """
    Manages all cryptographic operations for the client:
    - RSA key pair generation and decryption.
    - AES encryption for file transfers.
    """

    def __init__(self):
        self.private_key:Crypto.PublicKey.RSA.RsaKey = None

    def generate_rsa_keypair(self) -> tuple:
        """
        Generates a new 1024-bit RSA key pair.
        Returns a tuple: (private_key_base64_string, public_key_bytes)
        """
        # Generate a 1024-bit RSA key (matching the server's expected length)
        self.private_key = RSA.generate(1024)

        # Export the private key in DER format, then encode it to Base64
        # as requested by the assignment guidelines for 'me.info'
        der_private_key = self.private_key.export_key(format='DER')
        private_key_b64 = base64.b64encode(der_private_key).decode('utf-8')

        # Get the public key to send to the server
        public_key_bytes = self.get_public_key()

        return private_key_b64, public_key_bytes

    def load_private_key(self, private_key_b64: str) -> None:
        """
        Loads an existing RSA private key from a base64 encoded string.
        Typically read from the 'me.info' file.
        """
        try:
            der_private_key = base64.b64decode(private_key_b64)
            self.private_key = RSA.import_key(der_private_key)
        except Exception as e:
            raise ValueError(f"Failed to load the private RSA key: {e}")

    def get_public_key(self) -> bytes:
        """
        Exports the public key in DER format to be sent to the server.
        Strips the X.509 header to fit exactly into the 160 bytes limit.
        """
        if not self.private_key:
            raise RuntimeError("RSA key pair is not initialized.")

        # Creates a 162-byte X.509 key
        der_public_key = self.private_key.publickey().export_key(format='DER')

        # Strip the 22-byte X.509 header to get the 140-byte raw PKCS#1 key
        raw_key = der_public_key[22:]

        # Pad with zeros to reach exactly 160 bytes as expected by the server
        return raw_key.ljust(160, b'\x00')

    def decrypt_rsa(self, encrypted_aes_key: bytes) -> bytes:
        """
        Decrypts the AES key received from the server using the client's private RSA key.
        The server uses PKCS1 OAEP padding.
        """
        if not self.private_key:
            raise RuntimeError("RSA key pair is not initialized. Cannot decrypt.")

        try:
            # OAEP is the standard padding used by Crypto++ (C++) and expected by the server
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            return decrypted_aes_key
        except ValueError as e:
            raise ValueError(f"Failed to decrypt the AES key: {e}")

    def encrypt_aes(self, file_data: bytes, aes_key: bytes) -> bytes:
        """
        Encrypts the file content using the AES key provided by the server.
        Uses AES CBC mode with a zeroed Initialization Vector (IV) and PKCS7 padding.
        """
        if not aes_key or len(aes_key) != 32:
            raise ValueError("Invalid AES key. A 256-bit (32 bytes) key is required.")

        # The server expects the IV to be 16 bytes of zeros
        iv = b'\x00' * 16

        # Create the AES cipher in CBC mode
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

        # Crypto++ automatically pads data using PKCS7.
        # In pycryptodome, we must apply the padding manually before encrypting.
        padded_data = pad(file_data, AES.block_size)

        # Encrypt the padded data
        encrypted_data = cipher_aes.encrypt(padded_data)

        return encrypted_data

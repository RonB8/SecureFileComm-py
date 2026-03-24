from logging import raiseExceptions

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from User import *

class CryptoManager:
    """
    The CryptoManager class is responsible for managing cryptographic operations
    including generating and encrypting AES keys, as well as decrypting data
    using the AES encryption standard. It utilizes RSA for securely transferring
    the AES key.

    Attributes:
        public_key (bytes): The RSA public key used for encrypting the AES key.
        aes_key (bytes): The randomly generated AES key for symmetric encryption.
        iv (bytearray): The initialization vector used for AES encryption (CBC mode).
        aes_cipher (AES): The AES cipher object used for encryption and decryption.

    Methods:
        __init__(self, public_key: bytes = None) -> None:
            Initializes the CryptoManager with an optional public key.

        set_public_key(self, public_key: bytes) -> None:
            Sets the public key used for encrypting the AES key.

        get_public_key(self) -> bytes:
            Returns the current public key.

        generate_aes_key(self) -> None:
            Generates a new AES key and initializes the AES cipher with a zero-filled IV.

        get_aes_key(self) -> bytes:
            Returns the currently generated AES key.

        get_encrypted_aes_key(self) -> bytes:
            Encrypts the current AES key using the RSA public key and returns the encrypted key.

        decrypt_data(self, encrypted_data: bytes) -> bytes:
            Decrypts the given encrypted data using the current AES key and IV, and returns the decrypted data.
    """

    def __init__(self, public_key:bytes=None) -> None:
        self.public_key = public_key
        self.aes_key = None
        self.iv = None
        self.aes_cipher = None

    def set_public_key(self, public_key:bytes) -> None:
        self.public_key = public_key

    def get_public_key(self) -> bytes:
        return self.public_key

    def generate_aes_key(self) -> None:
        self.aes_key = get_random_bytes(32)

        # For the purpose of the project, the client assumes that the IV
        # is always filled with 0, although this is not a sure thing
        self.iv = bytearray([0 for _ in range(16)])

        self.aes_cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)

    def get_aes_key(self) -> bytes:
        return self.aes_key

    def get_encrypted_aes_key(self) -> bytes:
        if self.public_key is None:
            raise Exception('Encryption aes key failed. There is no public key.')

        if self.aes_key is None:
            raise Exception('Encryption aes key failed. There is no RSA key, you should generate one.')

        X509_HEADER = b'0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x00'
        rsa_public_key = RSA.import_key(X509_HEADER + self.public_key[:140])
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(self.aes_key)
        return encrypted_aes_key

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        if self.aes_key is None:
            raise Exception('Encryption aes key failed. There is no RSA key, you should generate one.')

        aes_cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        return aes_cipher.decrypt(encrypted_data)

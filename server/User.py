import uuid
from typing import Any
from CryptoManager import CryptoManager


class User:
    """
   The User class represents a client, containing information
   such as the user's ID, name, and cryptographic management. It handles
   the storage of encrypted content and decrypted files associated with the user.

   Attributes:
       __id (bytes): A unique identifier for the user.
       __name (str): The name of the user.
       crypto_manager (CryptoManager): An instance of CryptoManager for managing encryption/decryption.
       __encrypted_content (bytearray): Stores the encrypted content packets associated with the user.
       __temp_file_content (Any): Temporarily holds content that may be decrypted and saved.
       __decrypted_content (dict): A dictionary storing decrypted content with file names as keys.

   Methods:
       __init__(self, id: bytes, name: str, crypto_manager: CryptoManager):
           Initializes the User instance with an ID, name, and a CryptoManager instance.

       get_id(self) -> bytes:
           Returns the unique identifier of the user.

       get_name(self) -> str:
           Returns the name of the user.

       append_encrypted_packet(self, packet: bytearray) -> None:
           Appends an encrypted packet to the user's encrypted content.

       get_encrypted_content(self) -> bytearray:
           Returns a copy of the user's encrypted content.

       clear_encrypted_content(self) -> None:
           Delete the stored encrypted content.

       save_content_file(self, file_name: str, content: bytes) -> None:
           Saves decrypted content associated with a given file name.

       get_content_file(self, file_name: str) -> bytes:
           Retrieves the decrypted content for the specified file name.

       clear_content_file(self, file_name: str) -> None:
           Delete the decrypted content associated with the specified file name.
   """

    def __init__(self, id: bytes, name: str, crypto_manager:CryptoManager):
        self.__id = id
        self.__name = name
        self.crypto_manager = crypto_manager
        self.__encrypted_content = bytearray([])
        self.__temp_file_content = None
        self.__decrypted_content = {}

    def get_id(self) -> bytes:
        return self.__id

    def get_name(self) -> str:
        return self.__name

    def append_encrypted_packet(self, packet:bytearray) -> None:
        self.__encrypted_content += packet[:]

    def get_encrypted_content(self) -> bytearray:
        return self.__encrypted_content[:]

    def clear_encrypted_content(self) -> None:
        self.__encrypted_content.clear()

    def save_content_file(self, file_name:str, content: bytes) -> None:
        self.__decrypted_content[file_name] = content

    def get_content_file(self, file_name:str) -> bytes:
        return self.__decrypted_content[file_name]

    def clear_content_file(self, file_name:str) -> None:
         del self.__decrypted_content[file_name]


class UserRepository:
    """
    The UserRepository class manages the registration and retrieval of User instances.
    It stores a list of registered users and ensures that user IDs are unique.

    Attributes:
        repository (list): A list containing registered User instances.
        id_list (list): A list of unique user IDs to prevent duplicates.

    Methods:
        __init__(self):
            Initializes the UserRepository instance.

        register(self, name: str, crypto_manager: CryptoManager) -> User | None:
            Adds a new user with a unique ID and name.

        get_user(self, c_id: bytes) -> User | None:
            Retrieves a user by their unique ID.
    """

    def __init__(self):
        self.repository = []
        self.id_list = []

    def register(self, name: str, crypto_manager:CryptoManager):
        if any(usr.get_name() == name for usr in self.repository):
            print(f"The user {name} already exist")
            return None

        new_id = uuid.uuid4()
        while new_id in self.id_list:
            new_id = uuid.uuid4()

        self.id_list.append(new_id)
        new_user = User(new_id.bytes, name, crypto_manager)
        self.repository.append(new_user)
        print(f"Registering {name}")
        return new_user

    def get_user(self, c_id: bytes) -> Any | None:
        for usr in self.repository:
            curr_id = usr.get_id()
            if c_id == curr_id:
                return usr

        #If the user does not exist
        raise Exception(f'There is no user with ID: {c_id}')



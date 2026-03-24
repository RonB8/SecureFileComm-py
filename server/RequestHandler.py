from typing import Optional

from ByteFuncs import unpad
from DataBase import DataBase
from RequestParser import *
from Response import Response, Payload
from User import *
from cksum import checksum


class RequestHandler:
    """
    Class responsible for handling incoming requests from users, processing them,
    and generating appropriate responses.

    Attributes:
        users_list (UserRepository): Repository containing user data.
        data_base (DataBase): Database handler for storing and retrieving data about users' information and files.
    """

    def __init__(self, users_list: UserRepository, data_base: DataBase) -> None:
        self.users_list = users_list
        self.data_base = data_base

    def handle_request(self, request: RequestParser) -> Optional[bytearray]:
        """
               Handles an incoming request based on its code and dispatches it to the
               appropriate handling method.

               Args:
                   request (RequestParser): The parsed request object containing request data.

               Returns:
                   Optional[bytearray]: The response packet as a bytearray, or None if the request code is invalid.
               """

        handlers = {
            REGISTRY: self._handle_registry,
            SEND_PUBLIC_KEY: self._handle_send_public_key,
            LOGIN: self._handle_login,
            SEND_FILE: self._handle_send_file,
            VALID_CRC: self._handle_valid_crc,
            INVALID_CRC: self._handle_invalid_crc,
            FOURTH_INVALID_CRC: self._handle_fourth_invalid_crc
        }

        return handlers.get(request.code, lambda r: None)(request)

    def _get_user(self, client_id: bytes) -> User:
        """
        Retrieves a user from the repository based on the client ID.
        """

        return self.users_list.get_user(client_id)

    def _handle_registry(self, request: RequestParser) -> bytearray:
        """
       Handles user registration requests.

       Args:
           request (RequestParser): The registration request data.

       Returns:
           bytearray: The response packet indicating the result of the registration.
       """

        crypto_manager = CryptoManager()
        curr_user = self.users_list.register(request.get_name(), crypto_manager)

        if curr_user is None:
            response = Response(DEFAULT_VERSION, FAILED_REGISTRATION, 0, bytearray())
        else:
            self.data_base.add_client(curr_user.get_id(), curr_user.get_name())
            payload = Payload(c_id=curr_user.get_id())
            response = Response(DEFAULT_VERSION, SUCCESSFUL_REGISTRATION, len(payload.packet), payload.packet)

        return response.get_packet()


    # Receives from the client a public RSA key that is used by the server to securely send a symmetric AES key,
    # The AES symmetric key will be used to send files securely for the current login,
    # and the public RSA key will be saved and used for future sending of the AES symmetric key for that client.
    def _handle_send_public_key(self, request: RequestParser) -> bytearray:
        curr_user = self._get_user(request.client_ID)
        crypto_manager = curr_user.crypto_manager

        pub_key = request.get_public_key()
        self.data_base.set_public_key(curr_user.get_id(), pub_key)
        crypto_manager.set_public_key(pub_key)

        crypto_manager.generate_aes_key()
        aes_key = crypto_manager.get_aes_key()
        self.data_base.set_aes_key(curr_user.get_id(), aes_key)

        # Encrypt the AES key using the user's public key for secure transmission.
        encrypted_aes_key = crypto_manager.get_encrypted_aes_key()
        payload = Payload(c_id=request.client_ID, encrypted_aes_key=encrypted_aes_key)
        response = Response(DEFAULT_VERSION, PUBLIC_KEY_RECEIVED, len(payload.packet), payload.packet)

        return response.get_packet()

    # Generates a new symmetric AES key for the current login to be used to securely send files.
    # The AES key transfer will be done securely by the public key previously transferred by the client.
    # If no public key has been transferred, an error will occur.
    def _handle_login(self, request: RequestParser) -> bytearray:
        try:
            curr_user = self.users_list.get_user(
                request.client_ID)  # If the user does not exist an exception will be thrown
            crypto_manager = curr_user.crypto_manager

            crypto_manager.generate_aes_key()
            encrypted_aes_key = crypto_manager.get_encrypted_aes_key()
            aes_key = crypto_manager.get_aes_key()
            self.data_base.set_aes_key(curr_user.get_id(), aes_key)
            resp_code = LOGIN_ACCEPT
        except Exception as e:
            print(f"Login failed!\n{e}")
            encrypted_aes_key = None
            resp_code = LOGIN_DENIED

        payload = Payload(c_id=request.client_ID, encrypted_aes_key=encrypted_aes_key)
        response = Response(DEFAULT_VERSION, resp_code, len(payload.packet), payload.packet)

        return response.get_packet()

    # Receives from the client a file encrypted by the AES key he received,
    # if necessary the file will be sent in separate packets that each packet has an uniq request.
    # After receiving the entire file,
    # We will decrypt the file by the AES of the user stored in its encryption manager.
    # To verify that the contents of the file arrived correctly, we validate the CRC of the file.
    # If CRC authentication is successful,
    # the file is saved in the 'client files' folder or any other folder defined in the dataBase.
    def _handle_send_file(self, request: RequestParser) -> bytearray:
        curr_user = self._get_user(request.client_ID)
        crypto_manager = curr_user.crypto_manager

        #Ensure the content will not writen to existing file
        if request.get_packet_number() == 1:
            self.data_base.clear_encrypted_content(request.file_name())

        encrypted_packet = request.get_file_content()
        self.data_base.save_encrypted_packet(request.file_name(), encrypted_packet)

        print(f"Packet {request.get_packet_number().__str__()} from {request.total_packets()}")

        if request.get_packet_number() < request.total_packets(): #The full file steal not received
            payload = Payload(c_id= request.client_ID)

        else:
            encrypted_content = self.data_base.get_encrypted_content(request.file_name())
            decrypted_content = crypto_manager.decrypt_data(encrypted_content)
            decrypted_content = unpad(decrypted_content)

            self.data_base.clear_encrypted_content(request.file_name())

            # Save the file to verify CRC.
            # It will be deleted if CRC verification fails.
            # *May need to be handle if CRC authentication failures are not notified.
            file_path = self.data_base.save_file(request.file_name(), decrypted_content)

            # In accordance with the project's guidelines, saves the contents of the file in Ram as well
            curr_user.save_content_file(request.file_name(), decrypted_content)

            curr_check_sum = checksum(file_path.__str__())

            print(f"the crc is: {curr_check_sum}")
            payload = Payload(c_id=request.client_ID, content_size=request.get_content_size(),
                              file_name=request.file_name(), cksum=curr_check_sum)

        response = Response(DEFAULT_VERSION, VALID_FILE_ACCEPTED, len(payload.packet), payload.packet)

        return response.get_packet()

    # If the CRC validation is successful, we will not delete the file and update in the database that the CRC has been verified.
    def _handle_valid_crc(self, request: RequestParser) -> bytearray:
        print("valid crc")
        self.data_base.set_crc_verified(request.client_ID, request.file_name(), True)
        payload = Payload(c_id=request.client_ID)
        response = Response(DEFAULT_VERSION, MESSAGE_RECEIVED, len(payload.packet), payload.packet)

        return response.get_packet()

    # Returns a 'pong' message to the client for further CRC authentication attempts.
    def _handle_invalid_crc(self, request: RequestParser) -> bytearray:
        curr_user = self._get_user(request.client_ID)
        print("Invalid CRC")
        self.data_base.delete_file(request.file_name())
        curr_user.clear_content_file(request.file_name())
        pong = bytearray([0])
        return pong

    # If CRC validation fails, delete the file.
    def _handle_fourth_invalid_crc(self, request: RequestParser) -> bytearray:
        curr_user = self._get_user(request.client_ID)

        print("fourth invalid_crc")

        try:
            self.data_base.delete_file(request.file_name())
            curr_user.clear_content_file(request.file_name())
        except Exception:
            pass

        payload = Payload(c_id=request.client_ID)
        response = Response(DEFAULT_VERSION, MESSAGE_RECEIVED, len(payload.packet), payload.packet)

        return response.get_packet()

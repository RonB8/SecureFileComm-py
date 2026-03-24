import datetime
import os
import sqlite3
from typing import Any


class DataBase:
    """
   Represents a database connection for client and file management.

   Attributes:
       conn (sqlite3.Connection): Database connection object.
       cursor (sqlite3.Cursor): Cursor for executing SQL commands.
       directory (str): Path to the directory for storing client files.

   Methods:
       create_tables() -> None: Creates the clients and files tables if they do not exist.
       add_client(client_id: bytes, name: str) -> None: Adds a new client to the database.
       set_public_key(client_id: bytes, public_key: bytes) -> None: Updates the public key for a specified client.
       set_aes_key(client_id: bytes, aes_key: bytes) -> None: Updates the AES key for a specified client.
       add_file(client_id: bytes, file_name: str, path_name: str) -> None: Adds a new file record for a specified client.
       set_crc_verified(client_id: bytes, file_name: str, verified: bool) -> None: Updates the verified status of a specified file.
       get_client_by_id(client_id: bytes) -> dict | None: Retrieves a client's information by their unique identifier.
       get_file(client_id: bytes, file_name: str) -> dict | None: Retrieves a file's information by client ID and file name.
       close() -> None: Closes the database connection.
       save_file(file_name: object, content: object) -> object: Saves content to a specified file in the client's directory.
       delete_file(file_name: str) -> None: Deletes a specified file from the client's directory.
       save_encrypted_packet(file_name: str, encrypted_packet: bytes) -> None: Appends an encrypted packet to a specified file in the encrypted_files directory.
       get_encrypted_content(file_name: str) -> bytes: Retrieves the encrypted content of a specified file.
       clear_encrypted_content(file_name: str) -> None: Deletes the encrypted file associated with the specified file name.
   """

    def __init__(self, db_name: str="my_database.db", folder_name: str="client_files") -> None:
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()

        #initialize the folder of the client files
        self.directory = folder_name
        # Create the directory if it does not exist
        os.makedirs(self.directory, exist_ok=True)

    # Create the 'clients' and 'files' tables
    def create_tables(self) -> None:
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            ID BLOB PRIMARY KEY,
            Name TEXT NOT NULL,
            PublicKey BLOB,
            LastSeen TEXT,
            AESKey BLOB
        )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                ID BLOB,
                FileName TEXT NOT NULL,
                PathName TEXT NOT NULL,
                Verified BOOLEAN NOT NULL DEFAULT 0,
                PRIMARY KEY (ID, FileName)
            )
        ''')

        self.conn.commit()

    # Add a new client and set LastSeen to the current time
    def add_client(self, client_id: bytes, name: str) -> None:
        last_seen = datetime.datetime.now().isoformat()
        self.cursor.execute('''
        INSERT INTO clients (ID, Name, LastSeen) 
        VALUES (?, ?, ?)
        ''', (client_id, name, last_seen))
        self.conn.commit()

    # Update the PublicKey of a client
    def set_public_key(self, client_id: bytes, public_key: bytes) -> None:
        self.cursor.execute('''
        UPDATE clients 
        SET PublicKey = ?
        WHERE ID = ?
        ''', (public_key, client_id))
        self.conn.commit()

    # Update the AESKey of a client
    def set_aes_key(self, client_id: bytes, aes_key: bytes) -> None:
        self.cursor.execute('''
        UPDATE clients 
        SET AESKey = ?
        WHERE ID = ?
        ''', (aes_key, client_id))
        self.conn.commit()

    # Add a new file to the 'files' table
    def add_file(self, client_id: bytes, file_name: str, path_name: str) -> None:
        self.cursor.execute('''
        INSERT INTO files (ID, FileName, PathName)
        VALUES (?, ?, ?)
        ''', (client_id, file_name, path_name))
        self.conn.commit()

    # Initialize the 'Verified' status of a file
    def set_crc_verified(self, client_id: bytes, file_name: str, verified: bool) -> None:
        self.cursor.execute('''
        UPDATE files 
        SET Verified = ?
        WHERE ID = ? and FileName = ?
        ''', (verified, client_id, file_name))
        self.conn.commit()

    # Function to retrieve a client by ID
    def get_client_by_id(self, client_id: bytes) -> dict[str, Any] | None:
        self.cursor.execute('''
            SELECT ID, Name, LastSeen, PublicKey, AESKey FROM clients WHERE ID = ?
        ''', (client_id,))
        result = self.cursor.fetchone()  # Fetch the first matching row
        if result:
            return {
                'ID': result[0],
                'Name': result[1],
                'LastSeen': result[2],
                'PublicKey': result[3],
                'AESKey': result[4]
            }
        return None  # Return None if no client found


    # Function to retrieve a file by ID and file name
    def get_file(self, client_id: bytes, file_name: str) ->dict[str: Any] | None:
        self.cursor.execute('''
               SELECT ID, FileName, PathName, Varified FROM files WHERE ID = ? and FileName = ?
           ''', (client_id, file_name))
        result = self.cursor.fetchone()  # Fetch the first matching row
        if result:
            return {
                'ID': result[0],
                'FileName': result[1],
                'PathName': result[2],
                'Varified': result[3]
            }
        return None  # Return None if no file found


    # Close the connection when done
    def close(self) ->None:
        self.conn.close()

    def save_file(self, file_name: object, content: object) -> object:
        file_path = os.path.join(self.directory, file_name)
        mode = 'w' if isinstance(content, str) else 'wb'
        try:
            with open(file_path, mode) as file:
                file.write(content)
            print(f'File "{file_name}" created successfully in "{self.directory}".')
        except Exception as e:
            print(f'Error creating file: {e}')

        return file_path


    def delete_file(self, file_name: str) -> None:
        file_path = os.path.join(self.directory, file_name)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f'File "{file_name}" deleted successfully from "{self.directory}".')
            else:
                print(f'File "{file_name}" not found in "{self.directory}".')
        except Exception as e:
            print(f'Error deleting file: {e}')


    def save_encrypted_packet(self, file_name: str, encrypted_packet) -> None:
        base_name, _ = os.path.splitext(file_name)
        new_file_name = base_name + '.enc'
        file_path = os.path.join("../../SecureFileComm/Code Files/encrypted_files", new_file_name)

        # Ensure the directory exists
        os.makedirs("../../SecureFileComm/Code Files/encrypted_files", exist_ok=True)

        try:
            # Open the file in append mode
            with open(file_path, 'ab') as file:
                file.write(encrypted_packet)
            print(f'File "{new_file_name}" updated successfully in "encrypted_files".')
        except Exception as e:
            print(f'Error writing to file: {e}')


    def get_encrypted_content(self, file_name: str) -> bytes:

        base_name, _ = os.path.splitext(file_name)
        new_file_name = base_name + '.enc'

        file_path = os.path.join("../../SecureFileComm/Code Files/encrypted_files", new_file_name)

        try:
            # Open the file in binary mode and read the content as bytes
            with open(file_path, 'rb') as file:
                content = file.read()
            return content
        except FileNotFoundError:
            print(f'File "{new_file_name}" not found in "encrypted_files".')
            return b''  # Return empty bytes if file is not found
        except Exception as e:
            print(f'Error reading file: {e}')
            return b''  # Return empty bytes if any other error occurs

    def clear_encrypted_content(self, file_name: str) -> None:
        base_name, _ = os.path.splitext(file_name)
        new_file_name = base_name + '.enc'

        file_path = os.path.join("../../SecureFileComm/Code Files/encrypted_files", new_file_name)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f'File "{new_file_name}" deleted successfully from encrypted_files.')
            else:
                print(f'File "{new_file_name}" not found in encrypted_files')
        except Exception as e:
            print(f'Error deleting file: {e}')




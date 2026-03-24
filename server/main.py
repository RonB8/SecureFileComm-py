import warnings
from Server import Server


if __name__ == "__main__":

    HOST = ''
    PORT = 1256 #Default

    file_name = "port.info"

    try:
        with open(file_name, 'r') as f:
            content = f.read()
            PORT = int(content)
    except FileNotFoundError:
        warnings.warn(f'The \'{file_name}\' file does not exist')
    except ValueError:
        warnings.warn(f'The content of \'{file_name}\' is not a valid integer')

    try:
        # Initialization of all the properties required for communication with the client and working with the database
        server = Server(HOST, PORT)

        # Start listening to client requests
        server.start_listening()
    except:
        print("Something went wrong when opening the server")


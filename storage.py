

class LocalFileManager:
    def __init__(self):
        self.user_info_file = ""
        self.transfer_file = ""
        self.priv_key_file = ""

        self.ip_address = None
        self.port = None
        self.user_name = None
        self.file_path = None

    def read_transfer_info(self):
        self.ip_address = '127.0.0.1'
        self.port = 1234
        self.user_name = 'Israel Yehuda'
        self.file_path = 'secret.txt'

    def save_user_details(self, user_name=None, client_id=None, private_key=None):
        pass

    def get_private_key(self):
        pass


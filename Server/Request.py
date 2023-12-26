"""
This file implements the client's request by creating a class that represents it and handles each request
according to the request code respectively.

"""
import struct
import datetime
import uuid

from Crypto.PublicKey import RSA
from Crypto.Util import Padding

from Response import Response
from AESCipher import *
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

from cksum import *

# Request codes
REGISTRATION = 1025
SEND_PUBLICKEY = 1026
REGISTER_AGAIN = 1027
SEND_FILE = 1028
VALID_CRC = 1029
INVALID_CRC = 1030
INVALID_CRC_FINAL = 1031

NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
TOTAL_PAYLOAD_SIZE = 415
ID_SIZE = 16
PAD_SIZE = 16
IV_SIZE = 16
HEADER_SIZE = 23


def unpad_name(padded_name):
    # Find the index of the first occurrence of a non-zero character from the end
    last_nonzero_index = len(padded_name) - 1
    while last_nonzero_index >= 0 and padded_name[last_nonzero_index] == '0':
        last_nonzero_index -= 1

    # Extract the original string without trailing zeros
    unpadded_name = padded_name[:last_nonzero_index + 1]

    return unpadded_name


def unpad_bytes(padded_data):
    for i in range(len(padded_data) - 1, -1, -1):
        if padded_data[i] != 0:  # Assuming 0-byte padding
            return padded_data[:i + 1]
    return padded_data


def generate_encrypted_aes(public_key):
    aes_key_bytes = get_random_bytes(KEY_SIZE)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(aes_key_bytes), aes_key_bytes


def decrypt_aes(ciphertext, key):
    aes_cipher = AES.new(key, AES.MODE_CBC, iv=bytes(IV_SIZE))
    decrypted_bytes = aes_cipher.decrypt(ciphertext)
    decrypted_message = Padding.unpad(decrypted_bytes, AES.block_size)
    return decrypted_message


class Request:

    def __init__(self, client_socket, data, db, clients, files):
        self.last_seen = datetime.datetime.now()
        self.client_socket = client_socket
        self.client_id = uuid.UUID(bytes=data[:ID_SIZE])
        self.header = data[ID_SIZE:HEADER_SIZE]
        self.payload = data[HEADER_SIZE:]
        self.client_version, self.request_code, self.payload_size = struct.unpack('<chi',
                                                                                  self.header                                                                                 )
        self.db = db
        self.response = Response(self.client_socket, self.db)

        self.clients = clients
        self.files = files

    def handle_request(self):
        # Registration
        if self.request_code == REGISTRATION:
            client_name = unpad_name(self.payload.decode())
            if self.db.is_in_table(client_name):
                self.response.registration_no_success()
            else:
                client_uuid = self.response.registration_success()
                self.db.insert_registration_values(bytes(client_uuid),
                                                   client_name, self.last_seen)
            return False
        # The server received a public key from the client
        elif self.request_code == SEND_PUBLICKEY:
            # Extract the "Name" string (255 bytes)
            name = unpad_name(self.payload[:NAME_SIZE].decode())
            public_key_bytes = self.payload[NAME_SIZE:]
            public_key = RSA.import_key(public_key_bytes)
            ciphered_key, aes_key_bytes = generate_encrypted_aes(public_key)
            self.db.insert_keys(aes_key_bytes, public_key_bytes, self.last_seen, self.client_id.bytes)
            self.response.handle_public_key(name, self.client_id, ciphered_key)
            return False
        elif self.request_code == REGISTER_AGAIN:
            client_name = unpad_name(self.payload.decode())
            if self.db.is_in_table(client_name):
                public_key = self.db.get_public_key(client_name)
                ciphered_key, aes_key = generate_encrypted_aes(public_key)
                client_id = self.response.handle_reg_again_success(ciphered_key)
                self.db.re_reg(client_id, aes_key, client_name, self.last_seen)
            else:
                self.response.handle_reg_again_failed(client_name)
            return False
        elif self.request_code == SEND_FILE:
            content_size = int.from_bytes(self.payload[:4], byteorder='little')
            padded_file_name = self.payload[4:259].decode()
            file_name = padded_file_name.rstrip('0')
            file_path = os.path.abspath(file_name)
            self.db.insert_file_values(self.client_id.bytes, file_name, file_path)
            self.db.update_last_seen(self.client_id.bytes, self.last_seen)
            encrypted_message = self.payload[259:]
            aes_key_bytes = self.db.get_aes_key(self.client_id.bytes)[0]
            decrypted_message = decrypt_aes(bytes(encrypted_message), aes_key_bytes)
            with open("temp_file.txt", 'w') as temp_file:
                temp_file.write(decrypted_message.decode())
            result = readfile("temp_file.txt")
            checksum, length, filename = result.split('\t')
            self.response.handle_sent_file(self.client_id, int(length), filename, int(checksum))
            return False

        elif self.request_code == VALID_CRC or self.request_code == INVALID_CRC_FINAL:
            padded_file_name = self.payload.decode()
            file_name = padded_file_name.rstrip('0')
            self.db.update_last_seen(self.client_id.bytes, self.last_seen)
            self.db.update_verified(file_name)
            self.response.general_approval(self.client_id)
            self.send_to_client_list()
            self.send_to_file_list()
            return True
        elif self.request_code == INVALID_CRC:
            padded_file_name = self.payload.decode()
            file_name = padded_file_name.rstrip('0')
            self.db.update_last_seen(self.client_id.bytes, self.last_seen)
            self.db.delete_file(file_name)
            self.response.general_approval(self.client_id)
            return False

    def send_to_client_list(self):
        client_name = self.db.get_client_name(self.client_id.bytes)
        pub_key = self.db.get_public_key(self.client_id.bytes)
        aes_key_bytes = self.db.get_aes_key(self.client_id.bytes)[0]
        self.clients.add_to_list(self.client_id, client_name, pub_key, self.last_seen, aes_key_bytes)

    def send_to_file_list(self):
        file_name = self.db.get_file_name(self.client_id.bytes)
        file_path = self.db.get_file_path(self.client_id.bytes)
        verified = 1
        self.files.add_to_list(self.client_id, file_name, file_path, verified)

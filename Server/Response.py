"""
This file implements the server's response by creating a class that represents it and handles each response
according to the request code respectively.

"""

import uuid
import struct
import sys

# Response codes
REG_SUCCESS = 2100
REG_FAILED = 2101
AES_ISSUED = 2102
FILE_RECEIVED = 2103
GENERAL_APPROVAL = 2104
REG_AGAIN_APPROVED = 2105
REG_AGAIN_FAILED = 2106
GENERAL_ERROR = 2107

DUMMY_SIZE = 16
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
TOTAL_PAYLOAD_SIZE = 415
SERVER_VERSION = '3'


def pad_string_to_255_bytes(input_string):
    padded_string = input_string.ljust(255, '0')
    return padded_string


class Response:

    def __init__(self, client_socket, db):
        self.client_socket = client_socket
        self.server_version = SERVER_VERSION
        self.db = db

    def send_message(self, payload, payload_size, code):
        if payload is not None:
            message = struct.pack(
                '<chi',
                bytes(self.server_version, 'utf-8'),
                code,
                payload_size,
            ) + payload
        else:
            message = struct.pack(
                '<chi',
                bytes(self.server_version, 'utf-8'),
                code,
                payload_size,
            )
        self.client_socket.send(message)

    def registration_success(self):
        client_uuid = uuid.uuid4().bytes
        payload_size = len(client_uuid)
        code = REG_SUCCESS
        self.send_message(bytes(client_uuid), payload_size, code)
        return client_uuid

    def registration_no_success(self):
        payload_size = DUMMY_SIZE
        code = REG_FAILED
        payload = bytes([0] * 16)
        self.send_message(payload, payload_size, code)

    def handle_public_key(self, name, client_id, ciphered_key):
        if not self.db.is_in_table(name):
            payload_size = 0
            code = GENERAL_ERROR
            payload = None
            self.send_message(payload, payload_size, code)
        else:
            code = AES_ISSUED
            payload = client_id.bytes + ciphered_key
            payload_size = len(payload)
            self.send_message(payload, payload_size, code)

    def handle_sent_file(self, client_id, length, filename, checksum):
        code = FILE_RECEIVED
        padded_file_name = pad_string_to_255_bytes(filename)
        payload_size = len(client_id.bytes) + len(length.to_bytes(4, byteorder='little')) + \
                       len(padded_file_name) + len(checksum.to_bytes(4, byteorder='little'))
        payload = client_id.bytes + length.to_bytes(4, byteorder='little') + \
                  padded_file_name.encode() + checksum.to_bytes(4, byteorder='little')
        self.send_message(payload, payload_size, code)

    def general_approval(self, client_id):
        code = GENERAL_APPROVAL
        payload_size = len(client_id.bytes)
        self.send_message(client_id.bytes, payload_size, code)

    def handle_reg_again_success(self, ciphered_key):
        code = REG_AGAIN_APPROVED
        client_id = uuid.uuid4().bytes
        payload = client_id + ciphered_key
        payload_size = len(payload)
        self.send_message(payload, payload_size, code)
        return client_id

    def handle_reg_again_failed(self, name):
        payload = self.db.get_client_id(name)
        payload_size = sys.getsizeof(payload)
        code = REG_AGAIN_FAILED
        self.send_message(payload, payload_size, code)

    def general_error(self, client_id):
        code = GENERAL_ERROR
        payload_size = sys.getsizeof(client_id)
        self.send_message(code, payload_size, client_id.bytes)

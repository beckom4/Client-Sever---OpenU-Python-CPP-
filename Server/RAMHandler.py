"""
This file implements the data storage for clients that have already been created. .

"""
import Database
import sqlite3


class Clients:
    def __init__(self, db):
        self.db = db
        # If this is a server reboot - The list will be initialized with the dat in it.
        self.client_list = db.get_all_clients()

    def add_to_list(self, client_id, client_name, pub_key, last_seen, aes_key):
        client_tuple = (client_id, client_name, pub_key, last_seen, aes_key)
        self.client_list.append(client_tuple)


class Files:
    def __init__(self, db):
        self.db = db
        # If this is a server reboot - The list will be initialized with the dat in it.
        self.file_list = db.get_all_files()

    def add_to_list(self, client_id, file_name, path_name, verified):
        file_tuple = (client_id, file_name, path_name, verified)
        self.file_list.append(file_tuple)




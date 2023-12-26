"""
This file implements the database as a class each function represents an action that the client
can perform on the database.

"""

import sqlite3
import uuid

from Crypto.PublicKey import RSA


class Database:
    def __init__(self):
        db_path = "C:/Users/becko/PycharmProjects/mmn15(1)/defensive.db"
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.connection.cursor()

    def create_table_clients(self):
        self.cursor.execute("CREATE TABLE IF NOT EXISTS clients(ID BLOB PRIMARY KEY, Name TEXT,"
                            "PublicKey BLOB, LastSeen DATE, AESKey BLOB)")

    def create_table_files(self):
        self.cursor.execute("CREATE TABLE IF NOT EXISTS files(ID BLOB PRIMARY KEY, FileName TEXT, "
                            "PathName TEXT, Verified INTEGER)")

    def insert_registration_values(self, client_uuid, client_name, last_seen):
        query = "INSERT INTO clients (ID, Name, LastSeen) VALUES (?,?,?)"
        self.cursor.execute(query, (client_uuid, client_name, last_seen))
        self.connection.commit()

    def insert_keys(self, aes_key, public_key_bytes, last_seen, client_id):
        query = "UPDATE clients SET AESKey = ?, PublicKey = ?, LastSeen = ? WHERE ID = ?"
        self.cursor.execute(query, (aes_key, public_key_bytes, last_seen, client_id))
        self.connection.commit()

    def insert_file_values(self, client_id, file_name, path_name):
        query = "INSERT INTO files (ID, FileName, PathName, Verified) VALUES (?,?,?,?)"
        self.cursor.execute(query, (bytes(client_id), file_name, path_name, 0))
        self.connection.commit()

    def update_last_seen(self, client_id, last_seen):
        query = "UPDATE clients SET LastSeen = ? WHERE ID = ?"
        self.cursor.execute(query, (last_seen, client_id))
        self.connection.commit()

    def update_verified(self, file_name):
        query = "UPDATE files SET Verified = ? WHERE FileName = ?"
        self.cursor.execute(query, (file_name, 1))
        self.connection.commit()

    def re_reg(self, client_id, aes_key, name, last_seen):
        query = "UPDATE clients SET ID = ?, AESKey = ?, LastSeen = ? WHERE Name = ?"
        self.cursor.execute(query, (client_id, aes_key, last_seen, name))
        self.connection.commit()

    def get_aes_key(self, client_id):
        self.cursor.execute("SELECT AESKey FROM clients WHERE ID = ?", (client_id,))
        result = self.cursor.fetchone()
        return result

    def get_client_name(self, client_id):
        self.cursor.execute("SELECT Name FROM clients WHERE ID = ?", (client_id,))
        result = self.cursor.fetchone()
        return result

    def get_file_name(self, client_id):
        self.cursor.execute("SELECT FileName FROM files WHERE ID = ?", (client_id,))
        result = self.cursor.fetchone()
        return result

    def get_file_path(self, client_id):
        self.cursor.execute("SELECT PathName FROM files WHERE ID = ?", (client_id,))
        result = self.cursor.fetchone()
        return result

    def delete_file(self, file_name):
        self.cursor.execute("DELETE FROM files WHERE FileName = ?", (file_name,))
        self.connection.commit()

    def get_public_key(self, client_name):
        if self.is_in_table(client_name):
            self.cursor.execute("SELECT PublicKey FROM clients WHERE Name = ?", (client_name,))
            public_key_blob = self.cursor.fetchone()
            public_key_bytes = public_key_blob[0]
            public_key = RSA.import_key(public_key_bytes)
            # Now rsa_public_key contains your RSA public key
            return public_key

    def is_in_table(self, name):
        self.cursor.execute("SELECT * FROM clients WHERE Name = ?", (name,))
        # Fetch the result of the query
        res = self.cursor.fetchone()
        if res is not None:
            return True
        else:
            return False

    def is_table_empty_and_exists(self, table_name):
        # Check if the table exists
        self.cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
        table_exists = self.cursor.fetchone() is not None

        if not table_exists:
            # Close the cursor and connection
            return False, False

        # Execute a SELECT COUNT(*) query on the specified table
        self.cursor.execute(f"SELECT COUNT(*) FROM {table_name}")

        # Fetch the result
        count = self.cursor.fetchone()[0]

        # Check if the table is empty
        return table_exists, count == 0

    def get_all_clients(self):
        client_list = []
        if not self.is_table_empty_and_exists("clients"):
            # Execute a SELECT query
            self.cursor.execute("SELECT * FROM clients")

            # Fetch all rows
            rows = self.cursor.fetchall()

            # Iterate over rows
            for row in rows:
                # Each 'row' is a tuple, where each element corresponds to a column in the table
                client_uuid = uuid.UUID(bytes=row[0])
                client_name = row[1]
                public_key = RSA.import_key(row[2])
                last_seen = row[3]
                aes_key = row[4]
                current_row = tuple([client_uuid, client_name, public_key, last_seen, aes_key])
                client_list.append(current_row)

        return client_list

    def get_all_files(self):
        file_list = []
        if not self.is_table_empty_and_exists("files"):
            # Execute a SELECT query
            self.cursor.execute("SELECT * FROM files")

            # Fetch all rows
            rows = self.cursor.fetchall()

            # Iterate over rows
            for row in rows:
                # Each 'row' is a tuple, where each element corresponds to a column in the table
                client_uuid = uuid.UUID(bytes=row[0])
                file_name = row[1]
                path_name = RSA.import_key(row[2])
                verified = row[3]
                current_row = tuple([client_uuid, file_name, path_name, verified])
                file_list.append(current_row)
        return file_list

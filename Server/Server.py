"""
This file implements the server.  It runs an infinite loop that listens until a client wants
to connect and make a request. It allows multiple clients to connect via multithreading.

"""

import socket

from ClientThread import ClientThread
from RAMHandler import Clients, Files
from Database import Database

LOCAL_HOST = "127.0.0.1"
DEFAULT_PORT = 1357
PORT_MAX_NUM = 65535


def main():
    db = Database()
    clients = Clients(db)
    files = Files(db)
    db.create_table_clients()
    db.create_table_files()

    # Request a socket object from the Operation System to work with TCP/IP
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Extracting the port number from the file. If the file does not exist
    # or if the port number is illegal, use default port instead.
    try:
        with open("port.info", 'r') as file:
            temp_port = file.read()
            if not temp_port.isnumeric():
                print("Invalid port number - Default port will be used instead")
                port = DEFAULT_PORT
            else:
                port = int(temp_port)
                if port < 1 or port > PORT_MAX_NUM:
                    print("Invalid port number - Default port will be used instead")
                    port = DEFAULT_PORT
    # Extend the except to more errors for example unable to read, unable to open etc.
    except FileNotFoundError:
        print("Invalid port number - Default port will be used instead")
        port = DEFAULT_PORT
    except PermissionError:
        print("Invalid port number - Default port will be used instead")
        port = DEFAULT_PORT

    # Bind our server to local host and request that the server will listen on the given port
    server.bind((LOCAL_HOST, port))
    while True:
        server.listen(1)
        print("Server waits for client to connect...")
        client_socket, client_address = server.accept()
        new_thread = ClientThread(client_address, client_socket, db, clients, files)
        new_thread.start()


if __name__ == "__main__":
    main()

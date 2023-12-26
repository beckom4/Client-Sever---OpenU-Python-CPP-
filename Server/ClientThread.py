"""
This file implements the multithreading by creating a class that represents each client's connection
to the server.

"""

import threading

from Request import Request


class ClientThread(threading.Thread):
    def __init__(self, client_address, client_socket, db, clients, files):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.db = db
        self.clients = clients
        self.files = files
        print("New client at address: ", client_address)

    # The operating system calls this method (your code must NOT call this method)
    def run(self):
        client_local = threading.local()
        while True:
            data = self.client_socket.recv(1024)
            request = Request(self.client_socket, data, self.db, self.clients, self.files)
            is_finished = request.handle_request()
            if is_finished:
                print("Client disconnected")
                break

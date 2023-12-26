# Server-Client_OpenU_Python_CPP-

This project was the final assignment of the course "Defensive System Programming" in the Open University.

The goal of this project is to write a server in Python and a client in CPP, and set up encrypted communication between them. 

The encryption and communication protocol is as follows:
1. The client creates an RSA key and sends it to the server. 
2. The server creates an AES key and uses the RSA key to encrypt it. 
3. The client decrypts the encrypted AES key and uses it to encrypt its messages. 
4. The end goal is that the client sends a small encrypted file(Up to 50 KB) to the server, that decrypts it and uses checksum method authenticate its content.

The communication protocol(The client's requests and the server's responses are detailed in the the diagram that's in the pdf file in the project. 

Data handling: 
1. Each new/ updated client and its relevant information is stored in SQLITE3 database. 
2. Each new file and its relevant info is stored in SQLITE3 database. 
3. Accessing the database and/ or extracting data from it is done using SQLITE3.
4. All SQLITE3 commands are executed through Python's SQLITE3 interface. 


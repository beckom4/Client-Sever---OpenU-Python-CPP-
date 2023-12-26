#include "Request.h"

using namespace std;

using boost::asio::ip::tcp;
using boost::uuids::uuid;

// Struct to represent the header fields
struct Header {
    boost::uuids::uuid client_uuid = boost::uuids::nil_uuid();
    char client_version = '0';
    unsigned short code = 0;
    unsigned int payload_size = 0;
};


class Request {
public:
    Request(boost::asio::ip::tcp::socket& r_socket) : socket(r_socket) {}

    // Handling the registration request - Creating a message with the relevant 
    //                                     information, sending to the server and reading the response
    //                                     Making up to 3 attempts before fatal error
    void handle_registration(string client_name) {
        int counter = 0;
        short response_code = 0;
        // Making three attempts to send the message untill succeeding. 
        while (counter < 3) {
            vector<char> message = registration_request(client_name);
            vector<char> response(REG_SIZE);
            uuid uuid_value;
            error_code error;

            size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(message));

            size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(response.data(), REG_SIZE));

            char server_version = response[0];

            memcpy(&response_code, &response[1], sizeof(short));

            int payload_size;
            memcpy(&payload_size, &response[3], sizeof(int));

            copy(response.begin() + 7, response.end(), uuid_value.begin());
            if (response_code == REG_SUCCESS) {
                FileHandler file_handler_reg(uuid_value, client_name);
                file_handler_reg.create_me_file();
                header.client_uuid = uuid_value;
                break;
            }
            else {
                print_error();
            }
            counter++;
        }
        // After loop response code is 2101 -> Regitration failed 3 times
        if (response_code == REG_FAILED) {
            fatal_error();
        }
    }

    // Handling the public key request - Creating a message with the relevant 
    //                                     information, sending to the server and reading the response
    //                                     Making up to 3 attempts before fatal error
    void handle_public_key(string client_name) {
        int counter = 0;
        short response_code = 0;

        while (counter < 3) {
            FileHandler file_handler;

            header.code = SEND_PUBLIC_KEY;
            header.payload_size = PUB_KEY_PAYLOAD_SIZE;

            vector<char> message = create_header_vector();

            string padded_name = padName(client_name);

            message.insert(message.end(), padded_name.begin(), padded_name.end());

            // Creating the private key
            char pubkeybuff[RSAPublicWrapper::KEYSIZE];
            rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);

            // Adding the public key to the message vector and sending the message to the server.
            message.insert(message.end(), pubkeybuff, pubkeybuff + PUB_KEY_SIZE);
            size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(message));

            // get the private key, encode it as base64 and add it to priv.key and me.info
            std::string base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());
            file_handler.create_priv_key_file(base64key);
            file_handler.add_priv_to_me(base64key);

            string encrypted_aes = readMessage(socket, response_code);

            // create another RSA decryptor using an existing private key and decrypting the aes key
            RSAPrivateWrapper rsapriv_other(rsapriv.getPrivateKey());
            decrypted_aes = rsapriv_other.decrypt(encrypted_aes);		// 6. you can decrypt an std::string or a const char* buffer

            if (response_code == AES_ISSUED) {
                break;
            }
            counter++;
        }
        // If after 3 tries response code is not 2102 -> fatal error
        if (response_code != AES_ISSUED) {
            fatal_error();
        }
    }

    // Handling the re registration request - Creating a message with the relevant 
    //                                        information, sending to the server and reading the response
    //                                        Making up to 3 attempts before fatal error
    void handle_reg_again(string client_name) {
        int counter = 0;
        short response_code = 0;
 
        while (counter < 3) {
            FileHandler file_handler;

            vector<char> message = re_registration_request(client_name);

            size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(message));

            string encrypted_aes = readMessage(socket, response_code);

            // If re registration was successful - Update aes.
            if (response_code == REG_AGAIN_APPROVED) {
                // create another RSA decryptor using an existing private key and decrypting the aes key
                RSAPrivateWrapper rsapriv_other(rsapriv.getPrivateKey());
                decrypted_aes = rsapriv_other.decrypt(encrypted_aes);		// 6. you can decrypt an std::string or a const char* buffer
                break;
            }
            // If re registration was not approved - regiter again regularly
            else if (response_code == REG_AGAIN_FAILED) {
                handle_registration(client_name);
            }
            // Error from the server.
            else {
                print_error();
            }

            counter++;
        }
        // After loop response code is 2101 -> Regitration failed 3 times
        if (response_code == REG_AGAIN_FAILED) {
            fatal_error();
        }
    }

    // In this method, the file is read, its content encrypted, a message with it and with all other relevant data
    // is created and sent to the server. The response is read and handled in this method as well, including reading 
    // the checksum result sent by the server. 
    void send_file() {
        int counter = 0;
        short response_code = 0;
        while (counter < 3) {
            FileHandler file_handler;
            file_path = file_handler.get_file_path();
            string file_content = file_handler.get_content(file_path);
            int content_size = file_content.length();
            vector<char> message = send_file_request(content_size, file_path, file_content);
            size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(message));
            vector<char> response(FILE_RESPONSE_SIZE);
            size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(response.data(), FILE_RESPONSE_SIZE));
            // Getting the response code
            memcpy(&response_code, &response[1], sizeof(short));
            if (response_code == FILE_RECEIVED) {
                memcpy(&received_checksum, &response[FILE_RESPONSE_SIZE - INT_SIZE], sizeof(unsigned int));
                break;
            }
            counter++;
        }
        if (counter == 3) {
            fatal_error();
        }
    }

    // This method handles all the requests and responses that have to do with the crc. 
    // If the both checksums match, the method will send the approval to the server, expect an approval in return and terminate the program.
    // If they do not match, it will send the server a notice and send the file again, all that up to 4 times. 
    // After the 4th attempt, the program will terminate.
    void handle_crc() {
        short response_code = 0;
        Checksum csum;
        string s_checksum = csum.readfile(file_path);

        checksum = stoul(s_checksum);
        if (checksum == received_checksum) {
            int counter = 0;
            while (counter < 3) {
                send_valid_crc(socket, response_code);
                if (response_code == GENERAL_APPROVAL) {
                    break;
                }
                counter++;
            }
            // If the response code is different than 2104 after 3 loops -> Fatal error
            if (response_code != GENERAL_APPROVAL) {
                fatal_error();
            }
        }
        else {
            int invalid_crc_counter = 0;
            while (invalid_crc_counter < 3) {
                int counter = 0;
                while (counter < 3) {
                    send_invalid_crc(socket, response_code);
                    if (response_code == GENERAL_APPROVAL) {
                        break;
                    }
                    counter++;
                }
                // If the response code is different than 2104 after 3 loops -> Fatal error
                if (response_code != GENERAL_APPROVAL) {
                    fatal_error();
                }
                else {
                    send_file();
                }
                invalid_crc_counter++;
            }
            if (invalid_crc_counter == 3){
                int counter = 0;
                while (counter < 3) {
                    send_invalid_crc_final(socket, response_code);
                    if (response_code == GENERAL_APPROVAL) {
                        break;
                    }
                    counter++;

                }
                // If the response code is different than 2104 after 3 loops -> Fatal error
                if (response_code != GENERAL_APPROVAL) {
                    fatal_error();
                }
            }
        }
        
    }

private:
    Header header;
    
    tcp::socket& socket;
    
    string client_name;
    string decrypted_aes;
    string file_path;
   
    RSAPrivateWrapper rsapriv;

    unsigned int received_checksum = 0;
    unsigned int checksum = 0;


    // Creating the first header fields for registration request.
    void create_header(int payload_size) {
        header.client_version = CLIENT_VERSION;
        header.code = REGISTRATION;
        header.payload_size = payload_size;
    }

    // creating the header itself for sending as bytes.
    vector<char> create_header_vector() {
        // Create a vector of chars
        std::vector<char> bytes_vector;
        bytes_vector.insert(bytes_vector.end(), header.client_uuid.begin(), header.client_uuid.end());
        bytes_vector.push_back(header.client_version);
        bytes_vector.push_back(static_cast<char>(header.code & 0xFF));         // Low-order byte
        bytes_vector.push_back(static_cast<char>((header.code >> 8) & 0xFF));  // High-order byte
        bytes_vector.insert(bytes_vector.end(), reinterpret_cast<char*>(&header.payload_size),
            reinterpret_cast<char*>(&header.payload_size) + sizeof(header.payload_size));
        return bytes_vector;
    }

    // Preparing the rest of regitration request to be sent as bytes.
    vector<char> registration_request(string name) {
        // Since the server is going to ignore the uuid in this request:
        // Initialize dummy uuid to zeros and add it to the vector.
        header.client_uuid = boost::uuids::nil_uuid();
        string padded_name = padName(name);
        int payload_size = sizeof(padded_name.c_str());
        create_header(payload_size);
        vector<char> vector = create_header_vector();
        vector.insert(vector.end(), padded_name.begin(), padded_name.end());
        return vector;
    }

    // Preparing the payload of the re-regitration request to be sent as bytes.
    vector<char> re_registration_request(string name) {
        string padded_name = padName(name);
        int payload_size = sizeof(padded_name.c_str());
        header.code = RE_REG;
        header.payload_size = NAME_SIZE;
        vector<char> vector = create_header_vector();
        vector.insert(vector.end(), padded_name.begin(), padded_name.end());
        return vector;
    }

    // Preparing the message of request 1028(send file)
    vector<char> send_file_request(int content_size, string file_name, string file_content) {
        header.code = SEND_FILE;

        string padded_file_name = padName(file_name);

        // Generate a key and initialize an AESWrapper. You can also create AESWrapper with default constructor which will automatically generates a random key.
        const unsigned char* aes_char_ptr = reinterpret_cast<const unsigned char*>(decrypted_aes.c_str());
        AESWrapper aes(aes_char_ptr, AESWrapper::DEFAULT_KEYLENGTH);

        //  encrypt the message
        string ciphertext = aes.encrypt(file_content.c_str(), file_content.length());

        header.payload_size = INT_SIZE + NAME_SIZE + ciphertext.length();

        // decrypt a message (cipher text)
        std::string decrypttext = aes.decrypt(ciphertext.c_str(), ciphertext.length());

        // Creating the message vector - Adding header, content size, file name and content
        vector<char> vector = create_header_vector();
        vector.insert(vector.end(), reinterpret_cast<char*>(&content_size),
            reinterpret_cast<char*>(&content_size) + sizeof(content_size));
        vector.insert(vector.end(), padded_file_name.begin(), padded_file_name.end());
        vector.insert(vector.end(), ciphertext.begin(), ciphertext.end());

        return vector;
    }

    // Padding the client or file name with zeros to have 255 bytes. 
    string padName(const std::string& name) {
        if (name.size() >= NAME_SIZE) {
            // No need to pad, the string is already equal or longer than the target size
            return name;
        }
        size_t zerosNeeded = NAME_SIZE - name.size();
        return name + string(zerosNeeded, '0');
    }

    // Reading the messages from the server that have an RSA encrypted aes key in them and returning it.
    string readMessage(boost::asio::ip::tcp::socket& socket, short& response_code) {
        FileHandler file_handler;
        vector<char> header_vector(HEADER_SIZE);
        size_t bytes_read1 = boost::asio::read(socket, boost::asio::buffer(header_vector.data(), HEADER_SIZE));

        // Getting the response code
        memcpy(&response_code, &header_vector[1], sizeof(short));

        // Getting the payload size
        int payload_size = 0;
        memcpy(&payload_size, &header_vector[3], sizeof(int));

        vector<char> payload(payload_size);
        size_t bytes_read2 = boost::asio::read(socket, boost::asio::buffer(payload.data(), payload_size));

        // Reading the uuid and changing it int he file if it's a re-registration
        if (response_code == REG_AGAIN_APPROVED) {
            uuid uuid_value;
            vector<char> new_uuid(payload.begin(), payload.begin() + ID_SIZE);
            copy(new_uuid.begin(), new_uuid.end(), uuid_value.begin());
            header.client_uuid = uuid_value;
            file_handler.add_rereg_uuid(uuid_value);
        }
       
        // Reading the rest of the bytes from the message and extracting the aes
        vector<char> aes_bytes(payload.begin() + ID_SIZE, payload.end());

        string encrypted_aes(aes_bytes.begin(), aes_bytes.end());

        return encrypted_aes;
    }

    // Preparing and sending the message that approves both checksums match.
    void send_valid_crc(boost::asio::ip::tcp::socket& socket, short& response_code) {
        vector<char> response(GENERAL_APPROVAL_SIZE);
        header.code = VALID_CRC;
        header.payload_size = NAME_SIZE;
        string padded_file_name = padName(file_path);
        vector<char> message = create_header_vector();
        message.insert(message.end(), padded_file_name.begin(), padded_file_name.end());
        size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(message));
        size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(response.data(), GENERAL_APPROVAL_SIZE));
        memcpy(&response_code, &response[1], sizeof(short));
    }

    // Preparing and sending the message that says the checksums do not match.
    void send_invalid_crc(boost::asio::ip::tcp::socket& socket, short& response_code) {
        vector<char> response(GENERAL_APPROVAL_SIZE);
        header.code = INVALID_CRC;
        header.payload_size = NAME_SIZE;
        string padded_file_name = padName(file_path);
        vector<char> message = create_header_vector();
        message.insert(message.end(), padded_file_name.begin(), padded_file_name.end());
        size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(message));
        size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(response.data(), GENERAL_APPROVAL_SIZE));
        memcpy(&response_code, &response[1], sizeof(short));
    }
    
    // Preparing and sending the message that says the checksums did not match for the final time.
    void send_invalid_crc_final(boost::asio::ip::tcp::socket& socket, short& response_code) {
        vector<char> response(GENERAL_APPROVAL_SIZE);
        header.code = INVALID_CRC_FINAL;
        header.payload_size = NAME_SIZE;
        string padded_file_name = padName(file_path);
        vector<char> message = create_header_vector();
        message.insert(message.end(), padded_file_name.begin(), padded_file_name.end());
        size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(message));
        size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(response.data(), GENERAL_APPROVAL_SIZE));
        memcpy(&response_code, &response[1], sizeof(short));
    }

    void print_error() {
        cout << "Server responded with an error" << endl;
    }

    void fatal_error() {
        cout << "Fatal error - Failed to send message than 3 times." << endl;
        exit(1);
    }

};
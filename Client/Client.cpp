#include "Client.h"

using boost::asio::ip::tcp;
using boost::uuids::uuid;
using namespace std;

void print_error() {
	cout << "Server responded with an error" << endl;
}

int main()
{
	FileHandler file_handler;

	string host = file_handler.get_host();
	string port = file_handler.get_port();
	string client_name = file_handler.get_client_name();
	string file_path = file_handler.get_file_path();

	cout << "Client looking for connection" << endl;

	if (host.empty()) {
		cout << "Unable to connect" << endl;
		cout << "You might be tryint to register even though you alread are. " << endl;
		cout << "Please try again later." << endl;
	}				

	try {
		boost::asio::io_context ioContext;
		// The resolver resolves hostnames for establishing connections but doesn't connect itself. The socket is the one that does that. 
		tcp::resolver resolver {ioContext};

		//The result typw is what it's going to return.
		tcp::resolver::results_type endpoints = resolver.resolve(host, port);

		//Creating a socket
		tcp::socket socket{ioContext};

		// Connecting to the server
		boost::asio::connect(socket, endpoints);

		Request request(socket);

		request.handle_registration(client_name);
		request.handle_public_key(client_name);
		request.handle_reg_again(client_name);
		request.send_file();
		request.handle_crc();

	}
	catch (std::exception e) {
		std::cerr << "Exception in server: " << e.what() << std::endl;
	}
	cout << "Client finished running" << endl;

	return 0;
}

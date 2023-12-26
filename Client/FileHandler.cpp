
#include "FileHandler.h"

using namespace std;

using boost::uuids::uuid;

class FileHandler {
public:
	FileHandler() {
		me_file.open(me_file_name, ios::in);
		// me file doesn't exist
		if (!me_file.is_open()) {
			is_me = false;
			inst_file.open(file_name, ios::in);
			if (inst_file.is_open()) {
				int lineCount = 1;
				string line;
				while (getline(inst_file, line)) {
					if (lineCount == 1) {
						int dots_index = get_dots_index(line);
						int second_index = dots_index + 1;
						if (dots_index != -1) {
							host = line.substr(0, dots_index);
							port = line.substr(second_index);
						}
						else {
							file_error(2);
						}
					}
					else if (lineCount == 2) {
						client_name = line;
					}
					else if (lineCount == 3) {
						file_path = line;
					}
					else {
						file_error(3);
					}
					lineCount++;

				}

				inst_file.close();
			}
			else {
				file_error(1);
			}
		}
	}

	FileHandler(uuid client_uuid_received, string client_name_received) {
		client_uuid = client_uuid_received;
		client_name = client_name_received;
	}

	bool me_file_exists() {
		return is_me;
	}

	void file_error(int choice) {
		switch (choice) {
		case 1:
			cout << "File didn't open" << endl;
			break;
		case 2:
			cout << "Illegal statement in the first line" << endl;
			break;
		case 3:
			cout << "Instruction file has too many lines" << endl;
			break;
		case 4:
			cout << "Looks like you're already registered." << endl;
			break;
		case 5:
			cout << "File has fewer than two lines." << endl;
			break;
			exit(1);
		}
	}

	void create_me_file() {
		ofstream me_file("me.info");

		if (me_file.is_open()) {
			// Write the string to the file
			me_file << client_name << '\n';
			me_file << to_string(client_uuid) << '\n';
			// Close the file
			me_file.close();
			cout << "me.info created successfully" << endl;
		}
		else {
			file_error(1);
		}
	}

	void add_priv_to_me(string privkey) {
		// string base64key = Base64Wrapper::encode(privkey);
		// Read the existing content of the file
		ifstream inFile("me.info");
		if (!inFile) {
			file_error(1);
		}

		ostringstream fileContent;
		fileContent << inFile.rdbuf();
		inFile.close();

		string content = fileContent.str();
		size_t pos = content.find('\n'); // Find the first newline character
		if (pos != std::string::npos) {
			pos = content.find('\n', pos + 1); // Find the second newline character
			if (pos != std::string::npos) {
				content.insert(pos + 1, privkey + "\n"); // Insert the new string after the second newline
			}
			else {
				file_error(5);
			}
		}
		else {
			file_error(5);
		}

		// Write the modified content back to the file
		ofstream outFile("me.info");
		if (!outFile) {
			file_error(1);
		}

		outFile << content;
	}

	void create_priv_key_file(string privkey) {
		// string base64key = Base64Wrapper::encode(privkey);
		ofstream key_file("priv.key");

		if (key_file.is_open()) {
			// Write the string to the file
			key_file << client_name << privkey;
			// Close the file
			key_file.close();
			cout << "priv.key created successfully" << endl;
		}
		else {
			file_error(1);
		}
	}

	void add_rereg_uuid(uuid new_uuid) {
		// Open the file for reading and writing
		fstream file("me.info", ios::in | ios::out);

		if (!file.is_open()) {
			file_error(1);
		}

		// Read the existing content of the file into a vector of strings
		vector<std::string> lines;
		string line;
		while (std::getline(file, line)) {
			lines.push_back(line);
		}

		// Close the file
		file.close();

		// Update the second line with the new string
		if (lines.size() >= 2) {
			lines[1] = to_string(new_uuid);
		}
		else {
			file_error(1);
		}

		// Open the file again for writing (truncating the content)
		file.open("me.info", ios::out | ios::trunc);

		if (!file.is_open()) {
			file_error(1);
		}

		// Write the modified lines back to the file
		for (const auto& updatedLine : lines) {
			file << updatedLine << endl;
		}

		// Close the file
		file.close();
	}

	int get_dots_index(string s) {
		for (int i = 0; i < s.length(); i++) {
			if (s[i] == ':')
				return i;
		}
		return -1;
	}

	string get_client_name() {
		return client_name;
	}

	string get_host() {
		return host;
	}

	string get_port() {
		return port;
	}

	string get_file_path() {
		ifstream file("transfer.info");

		if (!file.is_open()) {
			file_error(1);
		}

		// Read the first two lines and discard
		std::string line;
		for (int i = 0; i < 2; ++i) {
			if (!std::getline(file, line)) {
				file_error(1);
			}
		}

		// Read and return the third line
		if (std::getline(file, line)) {
			return line;
		}
		else {
			file_error(1);
		}

	}

	string get_content(string file_name) {
		ifstream file(file_name);
		
		if (!file.is_open()) {
			file_error(1);
			return "dummy return";
		}

		stringstream buffer;
		buffer << file.rdbuf();

		file.close();

		return buffer.str();
	}

private:
	bool is_me = false;

	uuid client_uuid = boost::uuids::nil_uuid();

	string host;
	string port;
	string client_name;
	string file_path;
	string file_name = "transfer.info";
	string me_file_name = "me.info";

	fstream inst_file;
	fstream me_file;
};






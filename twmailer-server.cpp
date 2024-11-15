#include <iostream>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <string>
#include <thread>
#include <mutex>
#include <map>
#include <chrono>
#include <cstdlib>
#include <unistd.h>
#include <ldap.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define LDAP_PORT 389

using namespace std;
namespace fs = std::filesystem;

const int BUFFER_SIZE = 1024;
const int MAX_USERNAME_LENGTH = 8;
const int MAX_SUBJECT_LENGTH = 80;
const int MAX_LOGIN_ATTEMPTS = 3;
const int BLACKLIST_TIME = 60;  // Blacklist time in seconds 

// Mutexes for synchronization
mutex mail_mutex;
mutex session_mutex;
mutex blacklist_mutex;

// Struct for session data from logged-in users
struct Session 
{
    string username;
    bool is_authenticated;
};

map<int, Session> sessions;  // Map for client sessions
map<string, int> failed_login_attempts;  // Map for failed login attempts per IP
map<string, time_t> blacklist;  // Map for blacklisted IP addresses and expiration time

// LDAP server information
const string LDAP_HOST = "ldap.technikum-wien.at";
const string LDAP_BASE = "dc=technikum-wien,dc=at";

// Forward declarations
void handle_client(int client_socket, const string &client_ip);
void add_to_blacklist(const string &ip);
void load_blacklist();
void save_blacklist();
bool is_blacklisted(const string &ip);
bool authenticate_with_ldap(const string &username, const string &password);
string read_message(int client_socket);

// Main function
int main(int argc, char *argv[]) 
{
    if (argc != 2) 
    {
        cerr << "Expected input: ./twmailer-server <port>" << endl;
        return 1;
    }

    int port = atoi(argv[1]);
    load_blacklist();  // Load blacklist on server startup

    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) 
    {
        cerr << "Failed to create socket." << endl;
        return 1;
    }

    // Bind socket to IP/Port
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) 
    {
        cerr << "Failed to bind socket on port " << port << ". Error: " << strerror(errno) << endl;
        close(server_socket);
        return 1;
    }

    // Start listening
    if (listen(server_socket, 10) == -1) 
    {
        cerr << "Failed to listen on socket." << endl;
        close(server_socket);
        return 1;
    }

    cout << "Server listening on port " << port << "." << endl;

    while (true) 
    {
        sockaddr_in client_addr;
        socklen_t client_size = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_size);

        if (client_socket == -1) 
        {
            cerr << "Failed to accept client connection." << endl;
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);  // Thread-safe IP conversion
        thread client_thread(handle_client, client_socket, client_ip);
        client_thread.detach();  // Allow thread to run independently
    }

    close(server_socket);
    return 0;
}

// Methods
void handle_client(int client_socket, const string &client_ip) 
{
    char buffer[BUFFER_SIZE];
    int login_attempts = 0;
    int bytes_received;

    while (true) 
    {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_received <= 0) 
        {
            cerr << "Error: No data received or client disconnected." << endl;
            break;
        }

        string command(buffer);
        string command_data = "";
        command_data += string(buffer);
        stringstream ss(command_data); // ss is at the start of command_data
        getline(ss, command); // get the command, ss is the the point where the cursor is at the moment (at the start)
        cout << "This is a command " + command << endl;

        if (command == "LOGIN") 
        {
            if (is_blacklisted(client_ip)) 
            {
                send(client_socket, "Error: Blacklisted IP.\n", 23, 0);
                break;
            }

            string username, password;
            // Handle LOGIN
            memset(buffer, 0, BUFFER_SIZE);
            getline(ss, username); // get username, ss is the the point where the cursor is at the moment (after the command)
            

            memset(buffer, 0, BUFFER_SIZE);
            getline(ss, password); // get password, ss is the the point where the cursor is at the moment (after the username)

            if (authenticate_with_ldap(username, password)) 
            {
                // Successful login
                lock_guard<mutex> session_lock(session_mutex);
                sessions[client_socket] = {username, true};
                send(client_socket, "OK\n", 3, 0);
            } else 
            {
                // Failed login
                cout << "Failed LOGIN" << endl;
                login_attempts++;
                failed_login_attempts[client_ip]++;

                if (login_attempts >= MAX_LOGIN_ATTEMPTS) 
                {
                    add_to_blacklist(client_ip);
                    send(client_socket, "Error: Too many attempts. (Blacklisted)\n", 39, 0);
                    break;
                }
                send(client_socket, "Error: Invalid credentials.\n", 29, 0);
            }
        } else if (command == "SEND") 
        {
            lock_guard<mutex> session_lock(session_mutex);

            if (sessions[client_socket].is_authenticated) 
            {
                // Handle SEND command
                string receiver, subject, message;
                
                cout << "In the SEND command" << endl;
                // Get receiver
                memset(buffer, 0, BUFFER_SIZE);
                getline(ss, receiver);
                
                cout << receiver << " this is a receiver" << endl;
                // Get subject
                memset(buffer, 0, BUFFER_SIZE);
                getline(ss, subject);

                cout << subject << " this is a subject" << endl;
                if (subject.length() > MAX_SUBJECT_LENGTH) 
                {
                    send(client_socket, "Error: Subject too long.\n", 24, 0);
                    continue;
                }

                getline(ss, message);
                cout << message << " this is a message" << endl;

                // Store message in receiver inbox
                lock_guard<mutex> mail_lock(mail_mutex);
                fs::path inbox_path = "mail_spool/" + receiver + "_inbox";
                ofstream outfile(inbox_path, ios::app);
                
                cout << "After storing a message in reveiver box" << endl;
                if (!outfile) 
                {
                    send(client_socket, "Error: Failed to store message.\n", 33, 0);
                    continue;
                }

                outfile << "From: " << sessions[client_socket].username << "\n";
                outfile << "Subject: " << subject << "\n";
                outfile << message << ".\n";
                outfile.close();
                cout << "just send is left" << endl;

                send(client_socket, "OK\n", 3, 0);
            } else 
            {
                send(client_socket, "Error: Not logged in.\n", 23, 0);
            }
        } else if (command == "LIST") 
        {
            std::lock_guard<std::mutex> guard(session_mutex);
            if (sessions[client_socket].is_authenticated) 
            {
                // Handle LIST Command
                std::lock_guard<std::mutex> lock(mail_mutex);
                fs::path inbox_path = "mail_spool/" + sessions[client_socket].username + "_inbox";
                if (!fs::exists(inbox_path)) 
                {
                    send(client_socket, "0\n", 2, 0);
                    continue;
                }

                ifstream infile(inbox_path);
                string line, subjects = "";
                int count = 0;

                while (getline(infile, line)) 
                {
                    if (line.rfind("Subject:", 0) == 0) 
                    {
                        subjects += line.substr(8) + "\n";
                        count++;
                    }
                }
                infile.close();

                string response = to_string(count) + "\n" + subjects;
                send(client_socket, response.c_str(), response.length(), 0);
            } else 
            {
                send(client_socket, "Error: Not logged in\n", 20, 0);
            }

        } else if (command == "READ") 
        {
            std::lock_guard<std::mutex> guard(session_mutex);
            if (sessions[client_socket].is_authenticated) 
            {
                // Handle READ Command
                memset(buffer, 0, BUFFER_SIZE);
                int msg_num = atoi(buffer);

                std::lock_guard<std::mutex> lock(mail_mutex);
                fs::path inbox_path = "mail_spool/" + sessions[client_socket].username + "_inbox";
                if (!fs::exists(inbox_path)) 
                {
                    send(client_socket, "Error: Inbox not found\n", 21, 0);
                    continue;
                }

                ifstream infile(inbox_path);
                string line, message = "";
                int count = 0;

                while (getline(infile, line)) 
                {
                    if (line.rfind("Subject:", 0) == 0) 
                    {
                        if (count == msg_num) {
                            message += line + "\n";
                            while (getline(infile, line)) 
                            {
                                if (line == ".") break;
                                message += line + "\n";
                            }
                            break;
                        }
                        count++;
                    }
                }
                infile.close();

                if (message.empty()) 
                {
                    send(client_socket, "Error: Message not found\n", 24, 0);
                } else 
                {
                    send(client_socket, ("OK\n" + message).c_str(), message.length() + 3, 0);
                }
            } else 
            {
                send(client_socket, "Error: Not logged in\n", 20, 0);
            }

        } else if (command == "DEL") 
        {
            std::lock_guard<std::mutex> guard(session_mutex);
            if (sessions[client_socket].is_authenticated) 
            {
                // Handle DEL Command
                memset(buffer, 0, BUFFER_SIZE);
                int msg_num = atoi(buffer);

                std::lock_guard<std::mutex> lock(mail_mutex);
                fs::path inbox_path = "mail_spool/" + sessions[client_socket].username + "_inbox";
                if (!fs::exists(inbox_path)) 
                {
                    send(client_socket, "Error: Inbox not found\n", 21, 0);
                    continue;
                }

                ifstream infile(inbox_path);
                ofstream temp_out(inbox_path.string() + ".tmp");
                string line;
                int count = 0;
                bool deleted = false;

                while (getline(infile, line)) 
                {
                    if (line.rfind("Subject:", 0) == 0) 
                    {
                        if (count == msg_num) {
                            deleted = true;
                            while (getline(infile, line)) 
                            {
                                if (line == ".") break;
                            }
                        } else {
                            temp_out << line << "\n";
                        }
                        count++;
                    } else 
                    {
                        temp_out << line << "\n";
                    }
                }

                infile.close();
                temp_out.close();
                fs::remove(inbox_path);
                fs::rename(inbox_path.string() + ".tmp", inbox_path);

                if (deleted) 
                {
                    send(client_socket, "OK\n", 3, 0);
                } else 
                {
                    send(client_socket, "Error: Message not found\n", 24, 0);
                }

            } else 
            {
                send(client_socket, "Error: Not logged in\n", 20, 0);
            }

        } else if (command == "QUIT") 
        {
            send(client_socket, "OK\n", 3, 0);
            break; // End the client session

        } else 
        {
            send(client_socket, "Error: Invalid command\n", 21, 0);
            break; // This is a test
        }
        }

    lock_guard<mutex> session_lock(session_mutex);
    sessions.erase(client_socket);
    close(client_socket);
}

void add_to_blacklist(const string &ip) 
{
    lock_guard<mutex> blacklist_lock(blacklist_mutex);
    time_t expiration_time = time(nullptr) + BLACKLIST_TIME;
    blacklist[ip] = expiration_time;
    save_blacklist();  // Save updated blacklist
}

void load_blacklist() 
{
    ifstream blacklist_file("blacklist.txt");
    string ip;
    time_t expiration_time;

    while (blacklist_file >> ip >> expiration_time) 
    {
        blacklist[ip] = expiration_time;
    }
    blacklist_file.close();
}

void save_blacklist() {
    ofstream blacklist_file("blacklist.txt");
    for (const auto &entry : blacklist) 
    {
        blacklist_file << entry.first << " " << entry.second << endl;
    }
    blacklist_file.close();
}

bool is_blacklisted(const string &ip) 
{
    lock_guard<mutex> blacklist_lock(blacklist_mutex);
    if (blacklist.find(ip) != blacklist.end()) 
    {
        time_t now = time(nullptr);
        if (now < blacklist[ip]) 
        {
            return true;
        } else 
        {
            blacklist.erase(ip);
            save_blacklist();  // Save updated blacklist
            return false;
        }
    }
    return false;
}

bool authenticate_with_ldap(const string &username, const string &password) // Start here for troubleshooting LDAP Login...
{
    LDAP *ldap;
    int version = LDAP_VERSION3;
    int rc = ldap_initialize(&ldap, ("ldap://" + LDAP_HOST + ":389").c_str()); //this is a test


    if (rc != LDAP_SUCCESS) 
    {
        cerr << "Error: Could not connect to LDAP server. " << ldap_err2string(rc) << endl;
        return false;
    }

    ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
    string user_dn = "uid=" + username + ",ou=people," + LDAP_BASE; //this is a test

    // Debug message: Check the constructed user DN
    cout << "Debug: Attempting LDAP bind for DN: " << user_dn << endl;

    // Structure to hold password information for ldap_sasl_bind_s
    berval cred;
    cred.bv_val = const_cast<char *>(password.c_str());
    cred.bv_len = password.length();
    berval *servercredp; // this is a test

    // Debug message: Check if credentials are being set
    cout << "Debug: Credentials set, attempting LDAP bind..." << endl;

    // Using ldap_sasl_bind_s for simple authentication
    rc = ldap_sasl_bind_s(ldap, user_dn.c_str(), LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, &servercredp); //this is a test


    if (rc != LDAP_SUCCESS) 
    {
        cerr << "LDAP bind failed: " << ldap_err2string(rc) << endl;
        ldap_unbind_ext_s(ldap, nullptr, nullptr);  // Ensure clean unbind on failure
        return false;
    }

    // Successful bind message
    cout << "Debug: LDAP bind successful for user: " << username << endl;

    ldap_unbind_ext_s(ldap, nullptr, nullptr);
    return true;
}

string read_message(int client_socket) 
{
    string message;
    char buffer[BUFFER_SIZE];

    while (true) 
    {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) 
        {
            cerr << "Error: No data received or client disconnected." << endl;
            break;
        }

        string chunk(buffer);

        if (chunk == ".\n") 
        {
            break;  // End of message
        }

        message += chunk;
    }

    return message;
}
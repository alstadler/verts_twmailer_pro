#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sstream>

using namespace std;

const int BUFFER_SIZE = 1024;

// Forward declarations
void send_command(int client_socket, const string &command);
bool login(int client_socket);
void send_mail(int client_socket);
void list_mail(int client_socket);
void read_mail(int client_socket);
void delete_mail(int client_socket);
void handle_client_commands(int client_socket);
bool ensure_logged_in(bool is_logged_in);

// Main function
int main(int argc, char *argv[]) 
{
    if (argc != 3) 
    {
        cerr << "Expected input: ./twmailer-client <server-ip> <port>" << endl;
        return 1;
    }

    string ip = argv[1];  // Server IP address
    int port = atoi(argv[2]);  // Server port

    // Create socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) 
    {
        cerr << "Failed to create client socket." << endl;
        return 1;
    }

    // Setup server address structure
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) 
    {
        cerr << "Invalid IP address format." << endl;
        close(client_socket);
        return 1;
    }

    // Connect to server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) 
    {
        cerr << "Failed to establish server connection." << endl;
        close(client_socket);
        return 1;
    }

    cout << "Successfully connected to server." << endl;

    handle_client_commands(client_socket);  // Handle commands from client (LOGIN, SEND, LIST, READ, DEL, QUIT)

    close(client_socket);  // Close connection after QUIT or disconnection
    return 0;
}

// Methods
void send_command(int client_socket, const string &command) 
{
    send(client_socket, command.c_str(), command.size(), 0);  // Send command to server

    char buffer[BUFFER_SIZE];  // Buffer for response
    memset(buffer, 0, BUFFER_SIZE);

    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);  // Receive response from server

    if (bytes_received > 0) 
    {
        cout << buffer << endl;  // Output server response to console
    } else 
    {
        cerr << "Error: No response from server."<< endl;
    }
}

bool login(int client_socket) 
{
    string username;
    string password;

    cout << "Enter username: ";
    getline(cin, username);
    //cout << "Enter password: ";
    //getline(cin, password);
    password = getpass("Enter password: ");

    //send_command(client_socket, "LOGIN\n" + username + "\n" + password + "\n");  // Send LOGIN command and credentials to server
    const string command = "LOGIN\n" + username + "\n" + password + "\n"; // This is a test
    send(client_socket, command.c_str(), command.size(), 0); // This is a test

    char buffer[BUFFER_SIZE];  // Buffer for response
    memset(buffer, 0, BUFFER_SIZE);

    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);  // Receive response from server
    if (bytes_received > 0) 
    {
        if (string(buffer) == "OK\n") 
        {
            cout << "Login successful." << endl;
            return true;
        } else 
        {
            cout << buffer;  // Display error message from server
            return false;
        }
    } else 
    {
        cerr << "Error: No response from server during login." << endl;
        return false;
    }
}

void send_mail(int client_socket) 
{
    string receiver, subject, message, line;
    stringstream message_stream;

    cout << "Enter receiver username: ";
    getline(cin, receiver);  // Get receiver

    cout << "Enter subject (max 80 characters): ";
    getline(cin, subject);  // Get subject

    cout << "Enter message (end with a single period on a new line):" << endl;
    while (true) 
    {
        getline(cin, line);
        if (line == ".") break;
        message_stream << line << "\n";
    }
    
    send_command(client_socket, "SEND\n" + receiver + "\n" + subject + "\n" + message_stream.str() + ".\n");
}

void list_mail(int client_socket) 
{
    send_command(client_socket, "LIST\n");
}

void read_mail(int client_socket) 
{
    string message_number;

    cout << "Enter message number to read: ";
    getline(cin, message_number);  // Get message number

    send_command(client_socket, "READ\n" + message_number + "\n");  // Send READ command with message number to server
}

void delete_mail(int client_socket) 
{
    string message_number;

    cout << "Enter message number to delete: ";
    getline(cin, message_number);  // Get message number

    send_command(client_socket, "DEL\n" + message_number + "\n");  // Send DEL command with message number to server
}

bool ensure_logged_in(bool is_logged_in) 
{
    if (!is_logged_in) {
        cout << "Please log in first." << endl;
        return false;
    }
    return true;
}

void handle_client_commands(int client_socket) 
{
    bool is_logged_in = false;

    // Read commands until user quits or connection closes
    while (true) {
        string command;

        cout << "\nEnter command (LOGIN, SEND, LIST, READ, DEL, QUIT): ";
        getline(cin, command);  // Get command

        if (command == "LOGIN") 
        {
            if (!is_logged_in) 
            {
                is_logged_in = login(client_socket);  // Perform login function
            } else 
            {
                cout << "You are already logged in." << endl;
            }
        } else if (command == "SEND") 
        {
            if (!ensure_logged_in(is_logged_in)) continue;
            send_mail(client_socket);
        } else if (command == "LIST") 
        {
            if (!ensure_logged_in(is_logged_in)) continue;
            list_mail(client_socket);
        } else if (command == "READ") 
        {
            if (!ensure_logged_in(is_logged_in)) continue;
            read_mail(client_socket);
        } else if (command == "DEL") 
        {
            if (!ensure_logged_in(is_logged_in)) continue;
            delete_mail(client_socket);
        } else if (command == "QUIT") 
        {
            send_command(client_socket, "QUIT\n");
            break;  // Exit loop and close connection
        } else 
        {
            cout << "Invalid command. Please try again." << endl;
        }
    }
}
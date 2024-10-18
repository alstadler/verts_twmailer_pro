#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

const int BUFFER_SIZE = 1024;

// Forward declarations
void send_command(int client_socket, const string &command);    // Send command to server and recieve response
bool login(int client_socket);  // Handle login
void send_mail(int client_socket);   // Send message using SEND
void list_mail(int client_socket);  // List messages using LIST
void read_mail(int client_socket);  // Read message using READ
void delete_mail(int client_socket);    // Delete message using DEL
void handle_client_commands(int client_socket); // Handle user input

// Main function
int main(int argc, char *argv[])
{

    return 0;
}

// Methods
void send_command(int client_socket, const string &command)
{

}

bool login(int client_socket)
{

}

void send_mail(int client_socket)
{

}

void list_mail(int client_socket)
{

}

void read_mail(int client_socket)
{

}

void delete_mail(int client_socket)
{

}

void handle_client_commands(int client_socket)
{

}
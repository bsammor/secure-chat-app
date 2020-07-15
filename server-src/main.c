#include "server.h"

//takes as input the port number
int main(int argc, char **argv) {

	//if invalid input it exits
    if (argc != 2) {
      printf("Invalid input.\n");
      return -1;
    }

    unsigned short int port = atoi(argv[1]);

	//calls the function to create the server passing through the port number
    create_server_socket(port);
    printf("Server is running\n");
    open_db();

    while (1) {
      tick();
    }

    return 0;
}
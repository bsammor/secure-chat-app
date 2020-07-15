#include "client.h"


int main(int argc, char **argv) {
    if (argc != 3) {
        printf("invalid input.\n");
        return -1;
    }

    char *hostname = argv[1];    
    unsigned short int port = atoi(argv[2]);
    
    printf("Connecting to server %s:%s\n", argv[1], argv[2]);
    if (client_connect(hostname, port) == -1) {
        printf("Connection failed.\n");
    }
    else {
        printf("Connection succeeded.\n");
        while (1) {
            tick();
        }
    }
    return 0;
}
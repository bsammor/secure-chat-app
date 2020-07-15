#ifndef CLIENT_H
#define CLIENT_H

#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h> 
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include<sys/wait.h> 
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include "ssl-nonblock.h"

void init_client(char *host, int port_num);

int client_connect(const unsigned char *hostname, unsigned short port);

void send_message(unsigned char *message, int size);

void tick(void);

void read_input(void);

unsigned char* request_certificate(unsigned char *name);

void login_account(unsigned char *command);

void insert_account(char *name, void *key, int key_size);
#endif
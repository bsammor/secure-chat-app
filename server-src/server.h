#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include "database.h"
#include <unistd.h> 
#include <sys/time.h>
#include <sys/ipc.h> 
#include <sys/shm.h> 
#include <sys/mman.h>
#include <sys/wait.h> 
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <python3.6m/Python.h>
#include "ssl-nonblock.h"

void create_server_socket(unsigned short port);

void accept_connection(void);

void tick(void);

void send_message(int fd, char* message);

void worker_start(int serverfd);

void handle_input(int fd);

void notify_server(char *receiver);

void notify_worker(char *name);

void notify_all(void);

void get_users(void);

void login_account(char *header, char* name, char *sig);

void logout_account(void);

void register_account(char* name);

void public_message(char *message);

void private_message(char *receiver, char* message);

#endif
#include <sqlite3.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void open_db(void);

void insert_account(char *name);

void insert_message(char *sender, char* receiver, char *message);

int authenticate_account(char *name);

int accounts_exists(char *name);

char* get_latest_private(char *name);

char* get_latest_public(void);

char* get_all_messages(char *name);

void insert_cert(char *name, void *key, int key_size);

void* get_cert(char *name);

char *get_echo_message(char *name);
#include "database.h"

sqlite3 *db;

void open_db() {
    sqlite3_open("chat.db", &db);
}

//Query to insert an account into the accounts table
void insert_account(char *name) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO users (user_name, public_key) VALUES (?,?);", -1, &stmt, NULL);
    if(stmt != NULL) {
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
        sqlite3_bind_null(stmt, 2);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void insert_cert(char *name, void *key, int key_size) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "UPDATE users SET public_key = ? WHERE user_name = ?;", -1, &stmt, NULL);
    if(stmt != NULL) {
        sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
        sqlite3_bind_blob64(stmt, 1, key, key_size, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

void* get_cert(char *name) {
    void *key = malloc(1024);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT public_key FROM users WHERE user_name = ?;", -1, &stmt, NULL);
    if(stmt != NULL) {
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        key = (void *) sqlite3_column_blob(stmt, 0);
        sqlite3_finalize(stmt);
        return key;
    }
    return NULL;
}

//Query to insert a message into the message table
void insert_message(char *sender, char* receiver, char *message) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT INTO messages (sender, receiver, message, date_time) VALUES (?,?,?,julianday('now'));", -1, &stmt, NULL);
    if(stmt != NULL) {
        sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
        if (receiver != NULL)
            sqlite3_bind_text(stmt, 2, receiver, -1, SQLITE_STATIC);
        else 
            sqlite3_bind_null(stmt, 2);
        sqlite3_bind_text(stmt, 3, message, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

//Query to check if an account and password combination exists in the accounts table
int authenticate_account(char *name) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT EXISTS(SELECT 1 FROM users WHERE user_name = ?);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    int exists = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return exists;
}

//Query to check if an account username exists in the accounts table
int accounts_exists(char *name) {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT EXISTS(SELECT 1 FROM users WHERE user_name = ?);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    int exists = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return exists;
}

//Query to return the last private message for an account
char* get_latest_private(char *name) {
    char *message = (char *) malloc(1024 * sizeof(char*));
    memset(message, 0, 1024*sizeof(char));
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT date(date_time), time(date_time), sender, message FROM messages WHERE receiver = ? and ID = (SELECT MAX(ID) FROM messages);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
	snprintf(message, 1024, "%s %s %s: %s", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_text(stmt, 2), sqlite3_column_text(stmt, 3));
    sqlite3_finalize(stmt);
    return message;
}

char *get_echo_message(char *name) {
    char *message = (char *) malloc(1024 * sizeof(char*));
    memset(message, 0, 1024*sizeof(char));
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT date(date_time), time(date_time), sender, message FROM messages WHERE sender = ? and ID = (SELECT MAX(ID) FROM messages);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
	snprintf(message, 1024, "%s %s %s: %s", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_text(stmt, 2), sqlite3_column_text(stmt, 3));
    sqlite3_finalize(stmt);
    return message;
}

//Query to return the latest public message in the message table
char* get_latest_public(void) {
    char *message = (char *) malloc(256 * sizeof(char*));
    memset(message, 0, 256*sizeof(char));
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT date(date_time), time(date_time), sender, message FROM messages WHERE receiver IS NULL and ID = (SELECT MAX(ID) FROM messages);", -1, &stmt, NULL);
    sqlite3_step(stmt);
	snprintf(message, 256, "%s %s %s: %s", sqlite3_column_text(stmt, 0), sqlite3_column_text(stmt, 1), sqlite3_column_text(stmt, 2), sqlite3_column_text(stmt, 3));
    sqlite3_finalize(stmt);
    return message;
}

//Query to return all public and private messages in the message table for a specific account
char* get_all_messages(char *name) {
    char *message = (char *) malloc(1024 * sizeof(char*));
    memset(message, 0, 1024*sizeof(char));
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT date(date_time), time(date_time), sender, message FROM messages WHERE sender = ? OR receiver = ? OR receiver IS NULL ORDER BY id ASC;", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
    while (sqlite3_step(stmt) != SQLITE_DONE) {
        int i;
        int num_cols = sqlite3_column_count(stmt);
        
        for (i = 0; i < num_cols; i += 4) {
            char buffer[1024];
            snprintf(buffer, 1024, "%s %s %s: %s\n", sqlite3_column_text(stmt, i), sqlite3_column_text(stmt, i+1), sqlite3_column_text(stmt, i+2), sqlite3_column_text(stmt, i+3));
            strcat(message, buffer);
        }
    }
    sqlite3_finalize(stmt);
    message[strlen(message) - 1] = '\0';
    return message;
}
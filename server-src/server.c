#include "server.h"
#define MAXDATASIZE 1024


int clientfd;
int is_authenticated = 0;
char account_name[32];
int worker_pipes[10][2];

int serverfd;
int server_pipe[2];
int pipe_count = 0;
int count = 0;

fd_set read_fds;
fd_set master;

SSL *ssl;
X509 *cert;
SSL_CTX *ctx;

struct user {
	char name[16];
	int fd;
};

struct user online_users[10];

//loads cert and private key to CTX struct.
void load_cert() {
	const char* pathkey = "serverkeys/server-key.pem";
	const char* pathcert = "serverkeys/server-ca-cert.pem";
	SSL_CTX_use_certificate_file(ctx, pathcert, SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, pathkey, SSL_FILETYPE_PEM);
}

//inits the required structs.
void configure_SSL(void) {
	ctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_load_verify_locations(ctx, "ttpkeys/ca-cert.pem", NULL);
}

//sets the verification and starts SSL connection with new client.
void connect_SSL(void) {
	ssl = SSL_new(ctx);
	SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
	set_nonblock(clientfd);
	SSL_set_fd(ssl, clientfd);
	
	if (ssl_block_accept(ssl, clientfd) != 1) {
		fprintf(stderr, "verify result=%ld\n", SSL_get_verify_result(ssl));
		exit(1);
	}
}


void assign_pipefd(void) {
	for (int i = 0; i < 10; i++) {
		int free = 1;
		for (int j = 0; j < 10; j++) {
			if (online_users[j].fd == i) {
				free = 0;
				break;
			}		
		}
		if (free) {
			pipe_count = i;
			break;
		}
	}
}

void accept_connection(void) {
	pid_t pid;
	read_fds = master;

	//calls select
	if (select(serverfd+1,&read_fds,NULL,NULL,NULL) == -1){
        perror("select:");
        exit(1);
    }

	//checks for new clients and starts intializing them
    if (FD_ISSET(serverfd, &read_fds)) {
		clientfd = accept(serverfd, NULL, NULL);
	
		if (clientfd < 0) perror("accept");

		pid = fork();
		if (pid == (pid_t)-1) {}
		if (pid == 0) {
			connect_SSL();
			worker_start(clientfd);
		}
		pipe_count++;
	}

	//checks for communication between worker -> server
	if (FD_ISSET(server_pipe[0], &read_fds)) {
		//receives and stores the input into buf
		char buf[128];
		memset(&buf, 0, 128);
		read(server_pipe[0], buf, 128);
		//tokenize first part of input into header
		char *header = strtok(buf, " ");

		//public message command
		if (strcmp(buf, "null") == 0) {
			notify_all();
		}
		// /users command
		else if (strcmp(header, "/users") == 0) {
			//sets the fd of the worker that requested it
			int fd = atoi(strtok(NULL, " "));
			char users[128];
			memset(&users, 0, 128);
			//creates the online user list
			for (int i = 0; i<10; i++) {
				if (strcmp(online_users[i].name, "null") != 0) {
					strcat(users, online_users[i].name);
					strcat(users, " ");
				}
			}
			//writes to the pipe
			write(fd, users, sizeof(users));
		}
		// /login command
		else if (strcmp(header, "/login") == 0) {
			//set the name to add to online user list
			char *name = strtok(NULL, " ");
			int fd = atoi(strtok(NULL, " "));
			strcpy(online_users[count].name, name);
			online_users[count].fd = fd;
			count++;
		}
		// /exit command
		else if (strcmp(header, "/exit") == 0) {
			int fd = atoi(strtok(NULL, " "));
			//removes user from login list
			for (int i = 0; i < 10; i++) {
				if (online_users[i].fd == fd){
					strcpy(online_users[i].name, "null");
					online_users[i].fd = 0;
				}
			}
		}
		//handles private messaging
		else {
			notify_worker(buf);
		}
	}
}

void notify_worker(char *name) {	
	for (int i = 0; i < 10; i++) {
		//writes to the specific workers pipe
		if (strcmp(online_users[i].name, name) == 0) {
			write(online_users[i].fd, "private", sizeof("private"));
			break;
		}
	}		
}

void notify_all(void) {
	for (int i = 0; i < 10; i++) {
		//writes to every online users workers pipe
		if (online_users[i].fd != 0)
			write(online_users[i].fd, "public", sizeof("public"));
	}
}

void create_server_socket(unsigned short port) {
	int r;
	struct sockaddr_in addr;

	//loads certificate and configures the SSL objects
	configure_SSL();
	load_cert();

	//creates the server pipe
	pipe(server_pipe);

	//creates 10 different pipes, to be used by up to 10 clients
	for(int i=0; i<10; i++){
		pipe(worker_pipes[i]);
	}

	//create the array that will store online users
	for (int i = 0; i < 10; i++) {
		online_users[i].fd = 0;
		strcpy(online_users[i].name, "null");
	}

	//create TCP socket
	serverfd = socket(AF_INET, SOCK_STREAM, 0);
	if (serverfd < 0) perror("socket");

	//bind socket to specified port on all interfaces
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	r = bind(serverfd, (struct sockaddr*) & addr, sizeof(addr));
	if (r != 0) perror("bind");

	//start listening for incoming client connections
	r = listen(serverfd, 0);
	if (r != 0) perror("listen");

	//initializes datastructure for select for the server
	FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(serverfd,&master);
	FD_SET(server_pipe[0], &master);
}

//called repeatedly to continously accept incoming connections.
void tick(void) { 
    accept_connection();
}

/////////////////////////////////Worker//////////////////////////////////
void send_message(int fd, char* message) {
	int bytes_sent;
	bytes_sent = ssl_block_write(ssl, fd, message, strlen(message));
	if (bytes_sent == -1) {
		perror(NULL);
	}
}

//authenticates the user and logs in
void login_account(char *header, char* name, char *sig) {
	//checks if user is logged in
	if (is_authenticated == 1) {
		send_message(clientfd, "error: user is already logged in");
	}
	else {
		//calls the function to check if the user/pass matches an account in the database
		int is_registered = accounts_exists(name);

		if (is_registered == 0) {
			send_message(clientfd, "error: invalid credentials");
		}
		else {
			//the issue is here, no cert is being loaded when calling SSL_verify_client_post_handshake();
			cert = SSL_get_peer_certificate(ssl);
			//ERR_print_errors_fp(stderr);
			if (cert == NULL) {
				printf("no cert was loaded\n");
				exit(0);
			}
			const unsigned char* signature = (unsigned char *) sig;
			EVP_MD_CTX *ctx1 = EVP_MD_CTX_create();
			EVP_PKEY *evpKey = EVP_PKEY_new();
			evpKey = X509_get_pubkey(cert);
			int cert_size = i2d_X509(cert, NULL);

			if (get_cert(name) == NULL) {
				insert_cert(name, (void*) cert, cert_size);
			}

			char string[128];
			strcpy(string, header);
			strcat(string, " ");
			strcat(string, name);
		
			unsigned char *sig1; unsigned siglen1;
			sig1 = malloc(EVP_PKEY_size(evpKey));
			EVP_DigestInit(ctx1, EVP_sha256());
    		EVP_DigestUpdate(ctx1, string, strlen(string));
    		EVP_DigestFinal(ctx1, sig1, &siglen1);

			EVP_VerifyInit(ctx1, EVP_sha256());
			EVP_VerifyUpdate(ctx1, sig1, siglen1);
			is_authenticated = EVP_VerifyFinal(ctx1, signature, 256, evpKey);
			ERR_print_errors_fp(stderr);

			EVP_PKEY_free(evpKey);
			EVP_MD_CTX_free(ctx1);

			if (is_authenticated) {
				send_message(clientfd, "authentication succeeded");
				send_message(clientfd, get_all_messages(name));
				//create message to notify the server that the user is logged in and to add it to the list of online users
				char msg[64];
				snprintf(msg, 64, "%s %s %d", header, name, worker_pipes[pipe_count][1]);
				notify_server(msg);
				strcpy(account_name, name);
			}
			else {
				send_message(clientfd, "signature invalid");
			}
		}
	}
}

void logout_account(void) {
	//create message to notify the server that the user is logging out and to remove it from the list of online users
	char msg[64];
	snprintf(msg, 64, "%s %d", "/exit", worker_pipes[pipe_count][1]);
	notify_server(msg);
	exit(0);
}

void register_account(char* name) {
	//checking if username doesnt exist already
	if (!accounts_exists(name)) {
		//insert account details into the accounts table of the database
		insert_account(name);
		send_message(clientfd, "registration succeeded");
	}
	else {
		send_message(clientfd, "error: user already exists");
	}
}

void public_message(char *message) {
	//remove newline character
	message[strlen(message)-1] = '\0';
	//add message to the messages table in the database
	insert_message(account_name, NULL, message);
	//notify the server there is a new public message
	notify_server("null");
}

void private_message(char *receiver, char* message) {
	//gets rid of the @ and the newline character
	memmove(receiver, receiver + 1, strlen(receiver + 1) + 1);
	message[strlen(message)-1] = '\0';
	//add message to the messages table in the database
	insert_message(account_name, receiver, message);
	//notify the server there is a new private message for "receiver"
	send_message(clientfd, get_echo_message(account_name));
	notify_server(receiver);
}

void key_message(char *receiver, char *key) {
	char buffer[1024];
	memset(&buffer, 0 ,1024);
	snprintf(buffer, 1024, "/key %s", key);
	insert_message(account_name, receiver, buffer);
	notify_server(receiver);
}

void get_users(void) {
	char msg[64];
	snprintf(msg, 64, "%s %d", "/users", worker_pipes[pipe_count][1]);
	notify_server(msg);
}

void handle_input(int fd) {
	read_fds = master;

	if (select(clientfd+1,&read_fds,NULL,NULL,NULL) == -1) {
		perror("select:");
		exit(1);
    }

	//handle any input sent by the client
    if (FD_ISSET(clientfd, &read_fds) && ssl_has_data(ssl)) {
		char buffer[1024];
		memset(&buffer, 0, 1024);

		//stores the input in buffer, if it returns 0 it means the user disconnected without calling /exit and therefore logs out the user
		if (ssl_block_read(ssl, clientfd, buffer, sizeof(buffer)) <= 0) {
			logout_account();
		}

		//tokenize the input
		char buffer_copy[1024];
		strcpy(buffer_copy, buffer);
		char *header = strtok(buffer_copy, " ");
		char *name = strtok(NULL, " ");
		char *key = strtok(NULL, "");

		printf("%s %s\n", header, name);

		//large if/else statements which will handle all he different possible commands and call their respective functions
		if (strcmp(header, "/login") == 0 && name != NULL) {
			char sig[256];
			ssl_block_read(ssl, clientfd, sig, sizeof(sig));
			login_account(header, name, sig);
		}
		else if (strcmp(header, "/register") == 0 && name != NULL) {
			if (name[strlen(name)-1] ==  '\n')
				name[strlen(name)-1] = '\0';
			register_account(name);
		}
		else if (strcmp(buffer, "/exit\n") == 0) {
			logout_account();
		}
		else if (is_authenticated) {
			if (strcmp(header, "/users\n") == 0) {
				get_users();
			}
			else if (buffer[0] == '@') {
				private_message(header, buffer);
			}
			else {
				public_message(buffer);
			}
		}
		else {
			send_message(clientfd, "error: user is not currently logged in");
		}
	}

	//handle any input sent by the server
	if (FD_ISSET(worker_pipes[pipe_count][0], &read_fds)) {
		char buf[128];
		memset(&buf, 0, 128);
		read(worker_pipes[pipe_count][0], buf, 128);
		//lets the worker know it has a new private message
		if (strcmp(buf, "private") == 0) {
			char *msg = get_latest_private(account_name);
			send_message(clientfd, msg);
			free(msg);
		}
		//lets the worker know it has a new public message
		else if (strcmp(buf, "public") == 0) {
			char *msg = (char *) get_latest_public();
			send_message(clientfd, msg);
			free(msg);
		}
		//handles /users response
		else {
			send_message(clientfd, buf);
		}
	}
}

//initiating workers
void worker_start(int fd) {
	FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(clientfd,&master);
	FD_SET(worker_pipes[pipe_count][0], &master);
	
	while (1) {
		handle_input(fd);
	}
}

//send to server
void notify_server(char *receiver) {
    write(server_pipe[1], receiver, strlen(receiver));
}
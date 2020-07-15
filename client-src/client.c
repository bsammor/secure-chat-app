#include "client.h"
#define MAXDATASIZE 2048

int serverfd;
int port_num;
int authenticated = 0;
fd_set master;
fd_set read_fds;
SSL *ssl;
X509 *cert;
SSL_CTX *ctx;
char common_name[256];
char user_name[16];
char host_name[16];

/*static unsigned char *parsehex(const unsigned char *s, size_t len) {
  //quick and dirty way to parse hex string to binary data 
  unsigned char *buf = calloc(len, 1);
  for (int i = 0; s[i]; i++)
    buf[i/2] |= (s[i]%16 + (s[i]>>6)*9) << 4*(1-i%2);
  return buf;
}*/

//returns the IP of the domain found by the given hostname
static int lookup_host_ipv4(const char*hostname, struct in_addr *addr) {
    struct hostent *host;
    strcpy(common_name, hostname);

    host = gethostbyname(hostname);
    while (host) {
        if (host->h_addrtype == AF_INET && host->h_addr_list && host->h_addr_list[0]) {
            memcpy(addr, host->h_addr_list[0], sizeof(*addr));
            return 0;
        }
        host = gethostent();
    }
    return -1;
}

//inits the CTX and SSL structs for usage
void configure_SSL(void) {
    ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_load_verify_locations(ctx, "ttpkeys/ca-cert.pem", NULL);
    ssl = SSL_new(ctx);
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
}

void load_cert(void) {
    char certpath[128];
    char keypath[128];
    snprintf(keypath, 128, "clientkeys/%s-key.pem", user_name);
    snprintf(certpath, 128, "clientkeys/%s-ca-cert.pem", user_name);
    SSL_use_certificate_file(ssl, certpath, SSL_FILETYPE_PEM);
    SSL_use_PrivateKey_file(ssl, keypath, SSL_FILETYPE_PEM);
}

//starts up a SSL connection with the server and verifies identity.
void connect_SSL(void) {
    set_nonblock(serverfd);
    SSL_set_fd(ssl, serverfd);
    
    if (ssl_block_connect(ssl, serverfd) != 1) {
        fprintf(stderr, "verify result=%ld\n", SSL_get_verify_result(ssl));
        exit(1);
    }
    else {
        cert = SSL_get_peer_certificate(ssl);
        unsigned char *name = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        name += 4;
        if (strcmp(name, common_name) != 0) {
            printf("CN doesn't match\n");
            exit(1);
        }
    }
}

//establishes a connection between the client and the given server/port
int client_connect(const unsigned char *hostname, unsigned short port) {
    strcpy(host_name, hostname);
    port_num = port;

    struct sockaddr_in addr;
    int r;

    r = lookup_host_ipv4(hostname, &addr.sin_addr);
    if (r != 0)
        return -1;

    serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) perror("socket");

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    r = connect(serverfd, (struct sockaddr *) &addr, sizeof(addr));
    if (r != 0)
        return -1;

    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(0,&master);
    FD_SET(serverfd,&master);

    /* set up SSL connection with client */
    configure_SSL();
    connect_SSL();

    return 0;
}

//sends a message to the server
void send_message(unsigned char *message, int size) {
    int bytes_sent;
    bytes_sent = ssl_block_write(ssl, serverfd, message, size);
    if (bytes_sent == -1)
    {
        perror(NULL); 
        (exit(1));
    }
}

void read_input(void) {
    read_fds = master;

    //select in order to handle both user input and reading from socket without the use of multithreading.
    if (select(serverfd+1,&read_fds,NULL,NULL,NULL) == -1){
        perror("select:");
        exit(1);
    }

    //if the serverfd has data, read the data and print it.
    if (FD_ISSET(serverfd, &read_fds) && ssl_has_data(ssl)) {
        char socket_buffer[MAXDATASIZE];
        memset(&socket_buffer, 0, MAXDATASIZE);
        ssl_block_read(ssl, serverfd, socket_buffer, sizeof(socket_buffer));
        setvbuf(stdout, NULL, _IONBF, 0);
        printf("%s\n", socket_buffer);
    }
    

    //if the stdin fd has data, read the data and process it to server.
    if (FD_ISSET(0, &read_fds)) {
        char command[2048];
        memset(&command, 0, 2048);
        if (read(0, command, 2048) == 0) {
            exit(0);
        }

        char command_copy[2048];
		strcpy(command_copy, command);
		unsigned char *header = strtok(command_copy, " ");
		unsigned char *name = strtok(NULL, " ");

        setvbuf(stdout, NULL, _IONBF, 0);
        if (strcmp(command, "/exit\n") == 0) {
            send_message(command, strlen(command));
            exit(0);
        }
        else if (strcmp(header, "/register") == 0 && !authenticated) {
            strcpy(user_name, name);
            if (user_name[strlen(user_name)-1] == '\n') 
                user_name[strlen(user_name)-1] = '\0';
            send_message(command, strlen(command));

            char socket_buffer[256];
            memset(&socket_buffer, 0, 256);
            ssl_block_read(ssl, serverfd, socket_buffer, 256);
            if (strcmp(socket_buffer, "registration succeeded") == 0) {
                int pid = fork();
                if (pid == 0) {
                    execlp("python", "python", "gencert.py", user_name, (char*) NULL);
                }
                else wait(NULL);
                char login[64] = "/login ";
                strcat(login, user_name);
                strcat(login, "\n");
                login_account(login);
            }
        }
        //this entire block sends the /login username along with a signature to be checked by the server.
        else if (strcmp(header, "/login") == 0 && !authenticated) {
            strcpy(user_name, name);
            if (user_name[strlen(user_name)-1]== '\n') 
                user_name[strlen(user_name)-1] = '\0';

            char certpath[128];
            char keypath[128];
            snprintf(keypath, 128, "clientkeys/%s-key.pem", user_name);
            snprintf(certpath, 128, "clientkeys/%s-ca-cert.pem", user_name);
            if (access( certpath, F_OK ) != -1 && access( keypath, F_OK ) != -1 )
                login_account(command);
            else 
                printf("No certificate or private key file found\n");
        }
        else if (command[0] == '/') {
            printf("Invalid command\n");
        }
        else {
            send_message(command, strlen(command));
        }
    }
}

void send_signed_message(unsigned char *command) {
    unsigned char *sig; unsigned siglen;
    EVP_MD_CTX *ctx1 = EVP_MD_CTX_create();
    EVP_PKEY *evpKey = EVP_PKEY_new(); 

    char keypath[128];
    snprintf(keypath, 128, "clientkeys/%s-key.pem", user_name);
    FILE *keyfile = fopen(keypath, "r");
    RSA *privkey = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    fclose(keyfile);

    EVP_PKEY_assign_RSA(evpKey, privkey);
    sig = malloc(EVP_PKEY_size(evpKey));
    EVP_DigestInit(ctx1, EVP_sha256());
    EVP_DigestUpdate(ctx1, command, strlen(command));
    EVP_DigestFinal(ctx1, sig, &siglen);

    EVP_SignInit(ctx1, EVP_sha256());
    EVP_SignUpdate(ctx1, sig, siglen);
    EVP_SignFinal(ctx1, sig, &siglen, evpKey);

    send_message(command, strlen(command));
    send_message(sig, siglen);
}

void tick(void) {
    read_input();
}

void login_account(unsigned char *command) {
    SSL_shutdown(ssl);
    SSL_free(ssl);

    struct sockaddr_in addr;
    lookup_host_ipv4(host_name, &addr.sin_addr);

    serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) perror("socket");

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_num);
    connect(serverfd, (struct sockaddr *) &addr, sizeof(addr));

    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(0,&master);
    FD_SET(serverfd,&master);

    /* set up SSL connection with client */
    configure_SSL();
    load_cert();
    connect_SSL();
    
    command[strlen(command)- 1] = '\0';
    printf("%s\n", command);
    send_signed_message(command);

    char reply[128];
    memset(&reply, 0, 128);

    ssl_block_read(ssl, serverfd, reply, 128);
    printf("%s\n", reply);
    if (strcmp(reply, "authentication succeeded") == 0) {
        authenticated = 1;
    }
    else {
        SSL_shutdown(ssl);
        SSL_free(ssl);

        client_connect(host_name, port_num);
    }
}

/*unsigned char* request_certificate(unsigned char *name) {
    unsigned char message[1024];
    memset(&message, 0, 1024);

    snprintf(message, 1024, "/cert %s", name);
    send_message(message, strlen(message));

    unsigned char reply[2048];
    memset(&reply, 0, 2048);
    //ssl_block_read(ssl, serverfd, reply, 2048);

    return reply;
}*/
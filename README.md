#### Note: the tests pass if the user provides a username only since password authentication is not implemeted. (e.g "/login sam\n")

# Server and Client Communication overview:
## Client to Server: 
##### In order for the client to communicate with the server, the client accepts input from the user and sends it to the server socket that it is connected to when launching. The client accepts any input. This means that in order to check if the user input maps to an existing and accepted command, the parsing is done on the server side.

## Server to Client:
##### The server receives the input from a connected client, parses it, and if the input maps to an available command, executes it.

## Available Interactions:
### register-command: 
##### Overview: The client will firt be in a secure SSL connection with the server. Upon attempting to register, it will send the specified username to the server. Depending on the response from the server one of two things will happen. In the negative case where the server response with "user already exists" nothing will happen and the client will await for a new user input. In the positive case where the server response with "Registration Succeeded" the client will first generate a private key and a certificate for the user, it will then terminate the ssl connection and move onto the logging in process. This process will immediatly restabilish a ssl connection using the newly generated certficate as a way to authenticate to the server.
##### Authentication: required.
##### Data Layout: "/register username\n" (e.g: "/register sam\n")
##### Reply: "Registration Succeeded"
##### Error Reply: "error: user already exists"
##### Reference function: register_account()
##### Cryptography-Client: Client will contact the server asking if a user of X name is available, if not it will await furthur input, if so it will kill the connection and resestablish a secure connection for authentication.
##### Cryptography-Server: The servers connection being ssl is the only cryptography involved in the registration process. Once the client has registerd and moved onto the logging process the servers registration is over.

### login-command:
##### Overview: The client kills any existing SSL connections, and sets up a new connection to the server. The client then loads its certificate, and sends a login request to the server. Once the server receives the login request, the server verifies the client's certificate and authenticates the user. If authentication was successful, the user gets logged in and receives a login successful message. If the server couldn't authenticate the user, the SSL connection gets dropped and an error message is shown. And another ssl connection is established without a certificate loaded reseting the client to its original state.
##### Authentication: required.
##### Data Layout: "/login username" (e.g: "/login sam\n")
##### Reply: "Authentication Succeeded"
##### Error Reply: "error: invalid credentials", "error: user is already logged in"
##### Reference function: login_account()
##### Cryptography-Client: The message will be encrypted using SSL which has the users certificated loaded in. The message will also be acompanied by the digital signature of the client.
##### Cryptography-Server: The server checks the validatiy of both the certifcate and the signature. If both match and are valid authentication will be granted to that specific client. Otherwise an error message will be returned and authentication will fail.

### exit-command:
##### Overview: the client can exit the application by sending an exit command to the server to let them know that they are shutting down. the server then removes that user from the online users.
##### Authentication: not required.
##### Data layout: "/exit\n"
##### Reference function: logout_account()
##### Cryptography: Cryptography is not needed for this message as the only data being sent to the server is a /exit command, which holds no sensitive information.

### users-command:
##### Overview: The client uses this command in order to receive a list of every online user. Once the server receives the request, it gets the users from the online users list, stores them in a character array, and sends a reply containing the list which is then printed out to stdout by the client.
##### Authentication: required.
##### Data Layout: "/users\n"
##### Reply: "user1 user2 user3\n"
##### Reference function: get_users()
##### Cryptography: The only security needed is the established SSL connection that will protect the sensitve data being returned from the server to the client.

### publicmsg-command:
##### Overview: the client sends a public message to be sent to every account on the server. If the account is online, the server sends it to them to be printed out instantly. The message is received by the server and is stored in the database.
##### Authentication: required.
##### Data Layout: "this is a message\n"
##### Format from receiving end: "DATE TIME SENDER: MESSAGE" (e.g "2019-11-01 09:30:00 sam: this is a message\n")
##### Reference function: public_message()
##### Cryptography: Since the public chat is sent in a public channel, we assume that sensitive data will not be sent in this channel, so public messages do not require encryption, and therefore cryptography is not required. The connection will however still be protected by SSL.


### NOTE: we did not finish the implementation of private message. This section bellow will explain what we implemented. At the end of the readme will be another note detailing how we would have implemented the correct version of private message if more time was available.
### privatemsg-command:
##### Overview: the client sends a private message to a specific account on the server. If the account is online, the server sends it to them to be printed out instantly. If not it is still stored in the database and available to be loaded when they login.
##### Authentication: required.
##### Data Layout: "@user MESSAGE\n" (e.g, @sam hey how are you?\n")
##### Format from receiving end: "DATE TIME SENDER: @RECEIVER MESSAGE\n" (e.g "2019-11-01 09:30:00 erik: @sam hey how are you?\n")
##### Reference function: private_message()
##### Cryptography: The only security used is the established SSL connection that will protect the sensitve data being returned from the server to the client.


## Key management:
#### Client: Upon succesful registration the client will generate a certificate based on the CA certificate and a private key, this is done through python. These files are stored on disk in the clientkeys directory. Even though multiple clients keys will be stored in this same directory this is only due to the constraints of simulation a chat client on a single machine. Once logged in each client only has access to its own certificate and private key.  Upon attempting to login the client will locate the relevant certificate and private key files, embed the certificate into a new ssl connection and use the private key file to sign a message to the server.
#### Server: When "Make all" is run a server certificate based on the CA is generated along with a private key. When the server is run it will establish and ssl connection using its certficate to provide legitimacy to any possible connecting clients. These files are all stored in the serverkeys directory which only the server has access to and no client does.
#### TTP: This is also made in "Make all" creating the CA certificate the both the server and client rely on to generate their own certificates. It will be placed in the ttpkeys directory.


## Addressing Requirements:

* Mallory cannot read direct messages for which she is not either the sender or the intended recipient
##### This is solved by the connection being secured by ssl and authenticated with a valid certificate meaning only the intended clients will have acccess to private messages. 

* Mallory cannot send messages on behalf of another user.
##### This is solved and handled by the server authenticating the user at the start of the session by establishing an ssl connection with a valid certificate and signature. If the signature and certificate do not match the authetication is denied resulting in no message being able to be sent.

* Mallory cannot modify messages sent by other users.
##### Having an SSL secure connection would ensure that the data being transferred between a client and a server would not be modified.

* Mallory cannot find out users’ passwords or private keys (even if the server is compromised).
##### The server only stores the users username. The authetnication is done based on an SSL connection with a certificate embeded in it. Therefore even with full access to the accounts database there is no way to find out a users password, certificate or private key.

* Mallory cannot use the client or server programs to achieve privilege escalation on the systems they are running on. 
##### We will defend against SQL injections so any query done by the server is unable to alter the hierarchy of authorization of a specific user. We will make use of prepared statements in the part of our code that handles any interactions with the database. Prepared statements provide protection against SQL injection attacks, because the user can not directly alter the SQL queries sent to the database. Meaning, the data that is sent to the server by the user, gets subtituted by a parameter. The way this works is that the server executes the query first (ex. SELECT * FROM users WHERE name=?; ? is the parameter here), and after this query, the server sends the actual parameter (which was input by the user). This way, users can't alter queries that are stored in the server.

* Mallory cannot leak or corrupt data in the client or server programs. 
##### By not allowing buffer overflows the client and server will not leak memory and is not corruptible in this manner. 

* Mallory cannot crash the client or server programs.
##### We will establish many different limits on different aspects of the program/server, such as how many incoming connections are allowed as well as how many characters can be sent at once to limit the options of overloading the programs and causing them to crash.

* The programs must never expose any information from the systems they run on, beyond what is required for the program to meet the requirements in the assignments. 
##### The server will be supplied with privileges such that it can not access any data outside of the chat application. 

* The programs must be unable to modify any files except for chat.db and the contents of the clientkeys and clientkeys directories, or any operating system settings, even if Mallory attempts to force it to do so. 
##### The server will be hardcoded to be unable to modify anything besides these 3 files, and the clients cannot modify any files stored on the server. The server will be running on the least privilege level required for it to function.


### PRIVATE MESSAGE IMPLEMENTATION NOTE:
#### Our current implementation of private message does not meet the requirements as we were unable to implement our plan in time. Therefore we simply implemented a functional but not very secure version of private messaging. Due to the ssl connection it is still secure from outside threats, but any attack that gains access to the server will be able to see private messages along with the server itself being able to read them. In terms of our initial plan and what we were trying to implement is as follows. If client A wants to send a private message M to client B. It would first generate an AES symmetric key. It will then encrypt M with the AES key. However it also needs to send the key to client B along with the message so that client B can decrypt it. Therefore client A will request client B's public key from the server, the server has access to this information due to certificates being required for authentication/registration and therefore would have stored client B's public key. Once client A has client B's public key it will then RSA encrypt the AES key using client B's public key. Client A will then send the AES encrypted message and the RSA encrypted AES key to the server aswel as Client B's user. The server will then store "Client A" as the sender, "Client B" as the reciever, the AES encrypted message as the message and the RSA encrypted AES key as key1. It will then pass along the message, the RSA encrypted AES key and the sender (Client A) to client B. Client B will now use its own private key to decrypt the RSA encrypted AES key and use the resulting AES key to decrypt the messsage. The last step in the process will be for client B to re-encrypt the AES key with client A's public key and send this encrypted key back to the server. The server will then store the second RSA encrypted AES key into the table under key2. This allows both clients to access the encrypted message and using their specified AES key under either key1 or key2 to decrypt it. The server and any malicious access to the database will be unable to access the contents of the message as the private key of either client A or B is needed. We were unable to implement this specific implementation.
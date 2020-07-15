all:
	+$(MAKE) -C client-src 
	+$(MAKE) -C server-src 
	+$(MAKE) chat.db server-key.pem server-ca-cert.pem

ca-cert.pem: ca-key.pem
	openssl req -new -x509 -key ttpkeys/ca-key.pem -out ttpkeys/ca-cert.pem -nodes -sha256 -subj '/CN=ca\.example\.com/'

ca-key.pem:
	openssl genrsa -out ttpkeys/ca-key.pem

server-ca-cert.pem: ca-cert.pem ca-key.pem server-csr.pem
	openssl x509 -req -CA ttpkeys/ca-cert.pem -CAkey ttpkeys/ca-key.pem -CAcreateserial -sha256 -in serverkeys/server-csr.pem -out serverkeys/server-ca-cert.pem

server-csr.pem:
	openssl req -new -key serverkeys/server-key.pem -out serverkeys/server-csr.pem -nodes -subj '/CN=localhost/'

server-key.pem:
	openssl genrsa -out serverkeys/server-key.pem

chat.db:
	sqlite3 chat.db "CREATE TABLE messages(\
	id INTEGER PRIMARY KEY AUTOINCREMENT,\
	sender TEXT NOT NULL,receiver TEXT,\
	message TEXT NOT NULL,date_time REAL NOT NULL);\
	CREATE TABLE users(\
	user_name TEXT PRIMARY KEY,\
	public_key BLOB NULL);"

clean:
	-rm -f server
	-rm -f client
	-rm -f clientkeys/*
	-rm -f serverkeys/*
	-rm -f ttpkeys/*
	-rm -f chat.db
	-rm -f NUL

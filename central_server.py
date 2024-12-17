#
# Python central server that manages the login
# of clients as well as relaying encrypted messages between them. 
# This server is multi threaded. 
# 

import os
import sys
import socket

from threading import Thread
from threading import Lock

# We import Python's hashlib and base64 module for SHA256 and base64 encoding / decoding respectively. 
from hashlib import sha256
import base64



import signal

# We are using the 'cryptography' module for performing Elliptic Curve Diffie Hellman (ECDH),
# for establishing a shared secret for symmetric encryption (AES) 
# ECDH is used for establishing a shared secret for both, 
# intial communication with central server,
# as well as for establishing secure communication with individual users (like us)
# registered on the server's database. 

from cryptography.hazmat.primitives.asymmetric import ec

# We would need to encode & decode the public key in PEM format. 
from cryptography.hazmat.primitives import serialization

# We are using AES (Advanced Encryption Standard) for performing symmetric encryption. 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


##### The IP address & port of this central server #####
# This can be changed, but that change should be reflected in "clientapp.py"
SERVER_IP = "127.0.0.1"
PORT      =  8080

# Path to the database file containing the usernames & haahes of their passwords (base64 encoded) separated by ":"
DATABASE_FILE = "./database.txt"

# The maximum size of a response from the server. 
MAX_SIZE = 4096

# Global mutex lock object to protect race conditions while accessing critical resources
mutex_lock = Lock()


###### CRITICAL SECTION #######
# List of all client sockets ever returned by accept(..)
list_of_cli_socks = []
# The password database dictionary that maps usernames to password hashes. 
password_database = dict()

# The dictionary that maps the logged in user names to their socket file descriptors. 
users_logged_in = dict()

##### END OF CRITICAL SECTION #####

# Function to generate our (PEM encoded) public key & the private key (as an object) for performing ECDH
# Returns a tuple consisting of the PEM encoded public key (first element) and the private key object (secret) , that we can use for, 
# establishing the shared secret. 
def generate_ecdh_keys():
	# We are using the SECP256K1 elliptic curve. 
	# Because its security is widely accepted amd used for securing popular crypto currencies like Bitcoin. 
	private_key = ec.generate_private_key(ec.SECP256K1())
	
	# We obtain the PEM encoded public key from the private key 
	public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	
	
	# We send the public key and private key together as a tuple. 
	return (public_key, private_key)
	
# Function that performs ECDH, with the PEM encoded public key of the other client and our private key. 
# It returns a SHA256 hash of the shared secret. 
def establish_shared_secret_ecdh(public_key, private_key):
	shared_secret = b""
	
	# First we initialize the Elliptic Curve public key object from the PEM encoded data. 
	ec_public_key = serialization.load_pem_public_key(public_key)
	
	# The ECDH process is finally performed. 
	shared_secret = private_key.exchange(ec.ECDH(), ec_public_key)
	
	# Now we take the hash of the shared secret which returns a 32 byte byte-string. 
	shared_secret = sha256(shared_secret)
	# The hash is returned. This ensures that the shared secret key is always 32 bytes. 
	return shared_secret.digest()
	




# We implement the signal handler for handling SIGINT to stop our server. 
def signal_handler(signum, frame):
	# In the signal handler we make the "run" variable global and set it to False, so the server can stop gracefully.
	global run
	run = False
	
	global server_sock
	server_sock.close()



# Function that will run as a separate thread for handling every newly accepted connection. 
def handle_connection(cli_address, cli_socket):
	
	mutex_lock.acquire()
	print(f"[~] Thread handling: {cli_address} has started. ")
	mutex_lock.release()
	
	
	# The shared secret key for AES CTR encryption / decryption established after ECDH with client app. 
	shared_secret_key = b""
	
	# The cipher we use for encrypting / decrypting data using AES CTR
	cipher = None
	
	# The encryptor & decryptor objects. 
	enc = None
	dec = None
	
	# The flag that tells if login is successfull. 
	is_login_success = False
	# The base64 encoded username of this client. 
	client_username = ""
	
	
	# This connection handling thread must receive messages from the client app and perform actions based on the messages send from the client app. 
	# These actions could be performing ECDH for secure login / to generate new symmetric key when the old one expires. 
	# or it could be to relay messages from this client to another client app identified by their username. 
	while True:
		# First we must make sure if we are allowed to run! 
		mutex_lock.acquire()
		can_run = run
		mutex_lock.release()
		
		# The service loop is broken if we are not allowed to run. 
		if not can_run:
			break
			
		# We expect to receive a response of upto MAX_SIZE bytes from the client. 
		response = cli_socket.recv(MAX_SIZE)
		
		if(len(response) == 0):
			# We can stop service to this client. 
			break
		
		# If we have a shared secret key established then we must use that to decrypt the response from the server. 
		# Only then we will be able to process it!
		#However if response bytestring begins with b"ECDH" then we need to discard the already established shared secret, because the client wants to establish fresh shared secret with server! 
		if response.split(b":")[0] == "ECDH".encode("utf-8"):
			shared_secret_key = b""
			cipher = None
			enc = None
			dec = None
		
		
		print(f"Response received from: {cli_address}: {response}\n")
		if len(shared_secret_key) != 0:
			print(f"Ciphertext: {response}")
			# We decrypt the response with the previously established shared secret key 
			response = dec.update(response)
			print(f"Decrypted ciphertext: {response}")
			
		# Since our message has fields separated by ':' we tokenize based on the character ':'
		tokens = response.decode("utf-8").split(":")
		
		if tokens[0] == "ECDH":
			# This is our signal to perform ECDH with the client and generate a shared secret
			# that will be hashed using SHA256 to generate a symmetric key for AES encryption/decryption in counter mode. 
			# The second token is the public key of the client application in PEM encoded format. 
			# We load the public key object from the PEM encoded data. 
			client_public_key = serialization.load_pem_public_key(tokens[1].encode("utf-8"))
			
			# Now we generate our (the central server's ) public key and private key. 
			server_public_key, server_private_key = generate_ecdh_keys()
			
			# We send the server's public key to the client app so that it can establish the same shared secret using its own private key. 
			# Before we send the public key we prepend "ECDH:".encode("utf-8") before it. 
			cli_socket.send("ECDH:".encode("utf-8") + server_public_key)
			
			print("[~] Sending to {0}: {1}".format(cli_address, "ECDH:".encode("utf-8") + server_public_key))
			
			# Now we generate the shared secret ! 
			shared_secret_key = server_private_key.exchange(ec.ECDH(), client_public_key)
			
			# We take the SHA256 hash of the shared secret to obtain a 32 byte key. 
			shared_secret_key = sha256(shared_secret_key).digest()
			
			print(f"[~] Established shared secret: {shared_secret_key} with {cli_address}")
			
			# We initialize the cipher object to use the AES algorithm in counter (CTR) mode. 
			cipher = Cipher(algorithms.AES(shared_secret_key), modes.CTR(b"\x00" * 16))
			
			# We set up the encryptor and decryptor objects. 
			enc = cipher.encryptor()
			dec = cipher.decryptor()
			
			# If the client app is already logged in then we need to update the encryptor and decryptor objects in the dictionary mapping.
			if is_login_success:
				users_logged_in[client_username] = (cli_socket, enc, dec)
			
		elif tokens[0] == "Login":
			# We need to verify login information in tokens[1] & tokens[2] which is the username & password and send a b"SUCCESS" or b"WRONG PASSWORD" or b"UNKNOWN USER" response to the client app. 
			# All the responses are encrypted using AES in Counter mode. 
			# This byte string will be our response!
			our_response = b""
			
			# We need to verify the username & password. 
			print(f"[~] Verifying username: {tokens[1]} and password: {tokens[2]} from {cli_address}\n")
			
			# First we need to check if the username exists in our database. 
			username_exists = True # (We assume its true.)
			try:
				# Since the password database could be accessed by multiple threads, we use mutex locks to protect from race conditions. 
				mutex_lock.acquire()
				password_hash = password_database[tokens[1]]
				mutex_lock.release()
			except:
				# If an exception is thrown, then that means username does not exist!
				# We need to release the mutex!
				mutex_lock.release()
				username_exists = False
				
			if username_exists:
				# The username exists, now we need to check if the hash of the password matches.
				# First we need to calculate the hash of the provided password.
				# Decoding the base64 encoded string. 
				decoded = base64.b64decode(tokens[2].encode("utf-8"))
				
				# Next we compare the calculated hash with the hash stored in the database.
				if password_hash.encode("utf-8") == base64.b64encode(sha256(decoded).digest()):
					# Login is successfull! 
					is_login_success = True
					client_username = tokens[1]
					our_response = "SUCCESS".encode("utf-8")
					# We map the username to the socket file descriptor as well as with the encryptor and decryptor objects. 
					# This helps us to reference this client when other clients wants to send it messages. 
					mutex_lock.acquire()
					users_logged_in[tokens[1]] = (cli_socket, enc, dec) 
					mutex_lock.release()
				else:
					# The client has provided wrong password !
					our_response = "Wrong password !".encode("utf-8")
					
			else:
				# The username does not exist in our database!
				our_response = "Username not found in database of server! please register first !".encode("utf-8")
					
				
			print(f"[~] Plaintext response to {cli_address}: {our_response}")
			# We use our encryptor to encrypt the above response before sending to the client app. 
			our_response = enc.update(our_response)
			print(f"[~] Encrypted response (ciphertext) to {cli_address}: {our_response}")
			# Finally we send our encrypted response to the server. 
			cli_socket.send(our_response)
			
		elif tokens[0] == "Registration":
			# The client application wants to perform a registration of username and password with server database. 
			print(f"[~] Registration process for: {cli_address} initiated. ")
			
			# First we need to check if the username already exists in our database. 
			# Because if thats the case, then this registration process will not be allowed and the user has to try a different username. 
			username_found = True # We assume the username exists. 
			try:
				# Since the password database is a critical section we use a mutex lock. 
				mutex_lock.acquire()
				password_hash = password_database[tokens[1]]
				mutex_lock.release()
			except:
				# The mutex needs to be released.
				mutex_lock.release()
				username_found = False
				
			
			if not username_found:
				# Great! The username is not found in our database and we add the new username as well as the SHA-256 hash of their password to our database file. 
				# The username and hash of the password is base64 encoded and stored in the file. 
				# The username & password are separated by ":"
				# Since username sent by client app is already base64 encoded we dont have to encode it again!
				# The file is opened in append mode. 
				# This file is also a critical section. 
				mutex_lock.acquire()
				with open(DATABASE_FILE, "a") as fobj:
					# The password is hashed using SHA-256. 
					phash = sha256(base64.b64decode(tokens[2])).digest()
					record = tokens[1] + ":" + base64.b64encode(phash).decode("utf-8") + "\n"
					fobj.write(record)
					
					
				# Next we reload our database into memory since we updated it. 
				with open(DATABASE_FILE, "r") as fobj:
					for line in fobj:
						# All white space characters are removed. 
						line = line.strip()
						
						if len(line) != 0:
							# Since the username & password are separated by ":", we can tokenize based on that. 
							split_tokens = line.split(":")
							
							# The username & password is stored in our database.
							password_database[split_tokens[0]] = split_tokens[1]
							
				
				# Since the updated database is loaded into memory and we are done dealing with the critical section, the mutex lock can be released. 
				mutex_lock.release()
				
				# We store a SUCCESS response since the registration process is successfull! 
				our_response = "SUCCESS".encode("utf-8")
				
			else:
				# The username already exists and the client cannot register with an already existing username. 
				our_response = "Provided username already exists ! Please provide a different one !".encode("utf-8")
				
			
			# We print the plaintext response to the terminal. 
			print(f"[~] Response to {cli_address} as plaintext: {our_response}")
			
			# Finally our response is encrypted using the shared secret key using AES in CTR mode and send to the clientapp. 
			our_response = enc.update(our_response)
			
			# We print the ciphertext to the terminal. 
			print(f"[~] Response to {cli_address} as ciphertext: {our_response}")
			
			# The above response is sent to the client app. 
			cli_socket.send(our_response)
			
			
		elif tokens[0] == "MESSAGE":
			# The client wants to relay the message in tokens[2] to the username in "tokens[1]".
			# But first this makes sense only if the client is logged in. 
			if not is_login_success:
				# If the client wants to relay a message to another user without successfully logging in, in its a violation of protocol and hence we break service with such a client. 
				break
				
			print("[~] Relaying message: {0} to user: {1} from user: {2}".format(response, base64.b64decode(tokens[1].encode("utf-8")).decode("utf-8"), base64.b64decode(tokens[2].encode("utf-8")).decode("utf-8")))
				
			# Now the username of the destination client and the message to be sent are base64 encoded. 
			# Unless the message is the public key the message is encrypted with the shared secret the two client apps might have already established with each other. 
			# This secret key is unknown to the server. 
			# But, here the purpose of the server is to simply relay the message. 
			# This relay itself is encrypted again with the shared secret the other client app has established with the server at the time of login. So there is double security !
			
			if tokens[1] not in users_logged_in:
				# The requested user is not logged in yet!
				# So this will be our response!
				our_response = tokens[1]+":"+"Not logged in yet!"
				our_response = our_response.encode("utf-8")
				
				print("[~] Requested username not logged in! ")
				
				print(f"[~] Plaintext response to: {client_username}: {our_response}")
				
				our_response = enc.update(our_response)
				
				print(f"[~] Encrypted response (ciphertext) to {client_username}: {our_response}")
				# The above response is sent back to the client!
				cli_socket.send(our_response)
			else:
				# We relay the message to the user. 
				# But that message is encrypted with the encryptor / decryptor objects specific to that destination client app. 
				other_cli_sock, other_cli_enc, other_cli_dec = users_logged_in[tokens[1]]
				print(f"[~] Response to be relayed to: {client_username}: {response}")
				our_response = other_cli_enc.update(response)
				print(f"[~] Response relayed to {client_username} as CIPHERTEXT: {our_response}")
				# The above response is sent to destination client!
				other_cli_sock.send(our_response)
				
				
				
				
				
			
					
					
				
					
				
			
	
	# We remove the client socket from the list of sockets. 
	mutex_lock.acquire()
	list_of_cli_socks.remove(cli_socket)
	# We also remove the client from the list of successfully logged in users.
	if is_login_success:
		users_logged_in.pop(client_username)
	mutex_lock.release()	
	# The client socket is closed when connection handling is completed.
	cli_socket.close()


# Main entry point of our server application
def main():
	print("\t   * CENTRAL SERVER * ")
	
	# We need to load the database containing the user names and passwords. 
	if os.path.exists(DATABASE_FILE):
		with open(DATABASE_FILE, "r") as fObj:
			# We read the file line by line. 
			for line in fObj:
				# We remove leading & trailing white spaces. 
				line = line.strip()
				
				if len(line) != 0:
					# Every line contains the username & password SHA256 hash (all base64 encoded) separated by ":"
					tokens = line.split(":")
					
					# The username is mapped to the password hash and this mapping is made effective using a dictionary
					password_database[tokens[0]] = tokens[1]
					
	
					
	
	# We register the signal handler for SIGINT (Ctrl + C) so that the server can gracefully stop. 
	signal.signal(signal.SIGINT, signal_handler)
	
	# First we create a socket object for the server. 
	global server_sock
	server_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
	
	# We bind(..) the socket to the IP and port. 
	server_sock.bind((SERVER_IP, PORT))
	
	# We enable the socket to listen for incomming connections. 
	server_sock.listen(5)
	
	# Global flag that controls the running of the server. 
	global run
	run = True
	
	# List of thread objects we created. 
	threads = []
	
	
	
	print(("[*] Central Server started on (%s, %d), and waiting for incomming connections... \n") % (SERVER_IP, PORT))
	
	while run:
		# We wait to accept(..) a new connection.
		
		try:
			cli_sock, cli_address = server_sock.accept()
		except:
			# If we are unable to accept(..) a connection we simply continue. 
			continue
			
		
		# We append the socket descriptor to the list of all client sockets ever created. 
		# Since this list is a critical section we use mutex locks to protect the access. 
		mutex_lock.acquire()
		list_of_cli_socks.append(cli_sock)
		mutex_lock.release()
		
		t = Thread(target=handle_connection, args=(cli_address, cli_sock))
		# We start the thread! 
		t.start()
		
		# We append the thread object to the list of thread objects created. 
		threads.append(t)
		
		
		
		
	# We close all the client socket file descriptors. 
	for s in list_of_cli_socks:
		s.shutdown(socket.SHUT_RDWR)
		s.close()
	
	for t in threads:
		# The alive threads are joined to our main thread. 
		if t.is_alive():
			t.join()
	
	
	
	# The server socket is closed after use. 
	server_sock.close()
	
	
	
if __name__ == "__main__":
	main()

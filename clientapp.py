# The client application used for secure encrypted chatting. 
# This client will be used to chat with users that are registered on the server. 

# Standard Python modules. 
import os
import sys
import time
import socket
from threading import Thread
from threading import Lock

# We use the hashlib for the SHA256 hash function and base64 module for base64 encoding / decoding. 
from hashlib import sha256
import base64

# We are using Python's Tkinter library for the GUI
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import font


# We are using the cryptography module for performing Elliptic Curve Diffie Hellman (ECDH),
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





##### The IP address & port of the central server #####
# This can be changed, but that change should be reflected in "central_server.py"
SERVER_IP = "127.0.0.1"
PORT      =  8080

# The maximum size of a data transfer we expect from the server's socket. 
MAX_SIZE = 4096

# The expiry time in seconds after which we considered a shared secret key to be expired. 
EXPIRY_TIME = 120

# The minimum password length we require for new registrations. 
PASSWORD_LENGTH = 5

# We create a mutex object to protect access to shared resources. 
mutex_lock = Lock()



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
	
	

	
# The main application class, for our client! 
class ClientAPP:
	# The constructor of the class that takes the address of the central server's IP and port number. 
	
	def __init__(self, server_ip, port):
		# The 32 byte shared secret key used for AES CTR  encryption / decryption with the central server
		self.shared_secret_server = b""
	
		# The 32 byte shared secret key used for AES CTR encryption / decryption of the messages with the other user we are interested in communicating.
		self.shared_secret_user = b""
		# The time in which the shared secret key has been established with the other client 
		self.creation_time_ssu = 0
		# The cipher class we use for both encryption and decryption. 
		self.cipher = None
		# The encryptor & decryptor objects.
		self.enc = None
		self.dec = None
		# The flag that controls the running of the thread that waits for messages from other users through the central server. 
		self.run = False
		# Thread object. 
		self.thread = None
		
		# The public key that we use to establish a shared secret key for symmetric encryption with the other logged in user using the clientapp. 
		self.our_public_key = b""
		# The private key generated along with the above public key
		self.our_private_key = None
		
		
		
		# The cipher, the encryptor and the decryptor objects using the shared secret we established with the other user we are interested in communicating ! 
		self.cipher_ssu = None
		self.enc_ssu = None
		self.dec_ssu = None
		
		
		
		# First we create the socket for communicating with the central server. 
		self.serv_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
		
		
		
		# We try connecting with the central server, if we cannot connect we print an error and simply exit. 
		try:
			self.serv_sock.connect((server_ip, port))
		except:
			# We close the socket, print error and exit. 
			self.serv_sock.close()
			print(("[ERROR] Cannot connect to central server at: (%s, %d). Please make sure server is running & then try again! \n")%(server_ip, port))
			
			# We display an error message box. 
			messagebox.showerror(title="SecureP2P client. ", message=("[ERROR] Cannot connect to central server at: (%s, %d). Please make sure server is running & then try again! \n")%(server_ip, port))
			exit(1)
			
		# We create the main window of our application. 
		self.root = tk.Tk()
		# We set the title of our application. 
		self.root.title("SecureP2P client")
		
		# We initialize the font. 
		self.courier_font = font.Font(family="Courier", size = 10)
		
		# We create our first frame to hold all our widgets! 
		self.frm = ttk.Frame(self.root)
		self.frm.grid(row=0, column=0)
		self.login_logo = ttk.Label(self.frm, text = "LOGIN", foreground="green")

		# We create our username & password label
		self.uname_label = ttk.Label(self.frm, text="Username: ")
		self.passwd_label = ttk.Label(self.frm, text="Password: ")
		
		
		# Next we create our text entry widget for username & password. 
		self.uname_text = ttk.Entry(self.frm)
		self.passwd_text = ttk.Entry(self.frm, show="*")
		
		# We create our login button & registration button. 
		self.login_button = ttk.Button(self.frm, text="Login", command=self.login)
		self.registration_button = ttk.Button(self.frm, text="Register", command=self.register)
		
		# We create our string var object for storing username & password. 
		self.username = tk.StringVar()
		self.password = tk.StringVar()
		
		# We make the username text entry widget watch the username string var & password text entry widget watch the password string var. 
		self.uname_text["textvariable"] = self.username
		self.passwd_text["textvariable"] = self.password
		
		# Finally we place all the created widgets. 
		self.login_logo.grid(row=0, column=1)
		self.uname_label.grid(row=1, column=0)
		self.uname_text.grid(row=1, column=1)
		self.passwd_label.grid(row=2, column=0)
		self.passwd_text.grid(row=2, column=1, pady=10)
		self.login_button.grid(row=3, column=0, pady=10, padx=10)
		self.registration_button.grid(row=3, column=1, pady=10, padx=10)
		
		# We create a second frame below the first frame. 
		self.second_frame = ttk.Frame(self.root)
		self.second_frame.grid(row=1, column=0)
		
		# We create a label to produce a separation between the two frames. 
		self.separation_label = ttk.Label(self.second_frame, text="========= CRYPTOGRAPHIC INFORMATION =========== ")
		self.separation_label.grid(row=0, column=0, sticky=tk.EW)
		
		# We create a scrollable text widget for displaying all the details of the communication like ciphertext, plaintext, other communication information like public key, shared secret key etc. 
		self.text_widget = tk.Text(self.second_frame, height = 10, font = self.courier_font)
		self.text_widget.grid(row=1, column=0, sticky=tk.EW)
		
		# Since we want the above text widget to be scrollable we create the vertical scrollbar. 
		self.scroll_bar_widget = ttk.Scrollbar(self.second_frame, orient="vertical", command=self.text_widget.yview)
		
		# We place the scrollbar using grid()
		self.scroll_bar_widget.grid(row=1, column=1, sticky=tk.NS)
		
		# Next we link the text widget's Y scroll command to the scrollbar. 
		self.text_widget["yscrollcommand"] = self.scroll_bar_widget.set
		
		# We declare some widgets here, that will be created only later. 
		self.msend_button = None
		self.mtext_widget = None
		self.mentry_widget = None
		self.mscroll_bar = None
		self.mlabel = None
		self.mlabel_second = None
		self.message_var = tk.StringVar()
		
		# We set the window closing protocol. 
		self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
		
		# The main loop of the client application is started. 
		self.root.mainloop()
		
		#=============================================#
		# After the UI exits, this part gets executed #
		#=============================================#
		print("===== root.mainloop() ended =====\n")
		
		mutex_lock.acquire()
		self.run = False
		mutex_lock.release()
		# The socket is shutdowned.
		self.serv_sock.shutdown(socket.SHUT_RDWR)
		# We close the socket.
		self.serv_sock.close()
		
		if self.thread:
			if self.thread.is_alive():
				# The thread is joined.
				self.thread.join()
				
		
		
		
		
		
		
	# Function that performs the core logic of logging us in with the central server OR performing the registration with the provided username & password. 
	# The function performs login / registration depending on the string in 'action' function argument. 
	def _login_or_register(self, action):
		# We display detailed information on the listbox. 
		self.insert_to_text_widget(self.text_widget, tk.END, f"===== {action} PROCESS ===== \n")
		   
		# If we don't have a shared secret key established with the server we will need to create that now by performing Elliptic Curve Duffie Hellman with our server. 
		if len(self.shared_secret_server)==0:
			# We generate our Elliptic Curve (SECP256k1) public & private key pairs. 
			# Our private key must be kept secret. 
			# Our public key must be send to the server so it responds with its own public key.
			# The public key returned from generate_ecdh_keys(), is a PEM encoded byte string. 
			public_key, private_key = generate_ecdh_keys()
			# We send our public key to the central server to establish a shared secret that can be used for creating a symmetric key. 
			self.insert_to_text_widget(self.text_widget, tk.END, ("[*] Our public key: %s\n") % (public_key.decode("utf-8"),))
			   
			self.serv_sock.send("ECDH:".encode("utf-8") + public_key)
			# We finally receive the public key of the central server which we can use to establish the shared secret using our private key! 
			public_key_server = self.serv_sock.recv(MAX_SIZE).split(b":")[1]
			self.insert_to_text_widget(self.text_widget, tk.END, ("[*] Central server's public key: %s\n") % (public_key_server.decode("utf-8"),))
			   
			
			# Finally we can use the public key of the server and our private key to establish our shared secret. 
			self.shared_secret_server = establish_shared_secret_ecdh(public_key_server, private_key)
			self.insert_to_text_widget(self.text_widget, tk.END, "[*] Shared secret (base64 encoded): {0}\n".format(base64.b64encode(self.shared_secret_server).decode("ascii")))
			   
			
			# We instantiate a new cipher object for AES CTR encryption / decryption. 
			self.cipher = Cipher(algorithms.AES(self.shared_secret_server), modes.CTR(b"\x00"*16))
			self.enc = self.cipher.encryptor()
			self.dec = self.cipher.decryptor()
			
        #======================================================# 
		# We have already established the shared secret key for symmetric AES encryption and it is not expired yet! 
		# We can safely use it to encrypt our communication with the central server and send our username & password securely to the server.

		# We prepare to send the username and password to the server. 
		# NOTE: We base64 encode the username and password. 
		message = action.encode("utf-8") + ":".encode("utf-8") + base64.b64encode(self.username.get().encode("utf-8")) + ":".encode("utf-8") + base64.b64encode(self.password.get().encode("utf-8"))
		
		# The plaintext & ciphertext is printed. 
		self.insert_to_text_widget(self.text_widget, tk.END,f"Plaintext: {message}\n")
		   
		
		# We encrypt the above login / registration information with AES CTR encryption using the shared symmetric key 
		message_encrypted = self.enc.update(message)
		
		# The ciphertext is printed to the output window. 
		self.insert_to_text_widget(self.text_widget, tk.END,f"Ciphertext: {message_encrypted}\n")
		   
		
		# We send the above encrypted information to the server! 
		self.serv_sock.send(message_encrypted)
		
		# We collect the response from the server. 
		response = self.serv_sock.recv(MAX_SIZE)
		
		self.insert_to_text_widget(self.text_widget, tk.END,f"Ciphertext response: {response}\n")
		   
		# This response is decrypted and printed to the screen. 
		
		response = self.dec.update(response)
		
		self.insert_to_text_widget(self.text_widget, tk.END,f"Response as plaintext: {response}\n")
		   
		
		# We need to check if the login process was successfull. 
		if response.decode("utf-8") == "SUCCESS":
			# We display the message box telling the user that login / registration is successfully completed. 
			messagebox.showinfo(title="SecureP2P client", message=f"{action} Successfull !")
			# We return True to indicate that the operation got successfully completed. 
			return True
			
		else:
			# An error occured. 
			messagebox.showerror(title="SecureP2P client", message=response.decode("utf-8"))
			
		return False
			
	
	# Function that gets called when the "Login" button is pressed. 
	# This function calls self._login_or_register
	# with action set to "Login"
	def login(self):
		# We need to check if the user entered a username or password first. 
		if len(self.username.get()) == 0:
			messagebox.showerror(title="SecureP2P client", message="Please provide a username !")
			return
			
		if len(self.password.get()) == 0:
			messagebox.showerror(title="SecureP2P client", message="Please provide a password !")
			return
			
		
		ret = self._login_or_register("Login")
		
		if not ret:
			# If the login process failed, then we simply return without updating the UI, because the user needs to login successfully for the next step. 
			return
			
		# The login process is successful & we can update the user interface for messaging! 
		self.clear(self.frm)
		
		# We update the UI, so that the user can send and receive messages. 
		self.update_ui_for_messaging()
		
		# We start thread that will receive the incomming messages from the server. 
		self.start_monitoring_thread()
		
		# Since login is successfull we reflect that by adding the username to the title of our application. 
		self.root.title(f"SecureP2P client: {self.username.get()} (Logged in) ")

		

	# Function that gets called when the "Register" button is pressed. 
	# This function calls self._login_or_register
	# with action set to "Registration"
	def register(self):
		# If there is no username we don't perform the registration
		if len(self.username.get()) == 0:
			# We show proper error message box.
			messagebox.showerror(title="SecureP2P client", message="Please provide a username !")
			return
			
		# If the password length is less than PASSWORD_LENGTH characters we don't allow registration
		if len(self.password.get()) < PASSWORD_LENGTH:
			# We show proper error message box
			messagebox.showerror(title="SecureP2P client", message=f"Please provide a password that has atleast {PASSWORD_LENGTH} characters.")
			return
		
		self._login_or_register("Registration")
		
		
	# Function to clear all widgets from a given frame. 
	def clear(self, frame):
		for w in frame.winfo_children():
			w.destroy()
			
	# This function updates the UI, providing widgets for entering messages, button for sending the message and scrollable text widget for displaying messages 
	def update_ui_for_messaging(self):
		# First we create the text widget for displaying messages from the other clients. 
		self.mtext_widget = tk.Text(self.frm, height = 5, font=self.courier_font)
		# Next we create the entry widget for writing our messages. 
		self.mentry_widget = ttk.Entry(self.frm, font=self.courier_font)
		
		# We make the entry widget watch the string variable. 
		self.mentry_widget["textvar"] = self.message_var
		
		# We create the scroll bar widget for the scrollable text view so that we can see a history of messages from the other user. 
		self.mscroll_bar = ttk.Scrollbar(self.frm, orient="vertical", command=self.mtext_widget.yview)
		
		# Next we connect the text widget to the scrollbar's set method. 
		self.mtext_widget["yscrollcommand"] = self.mscroll_bar.set
		
		# Next we create our send button. 
		self.msend_button = ttk.Button(self.frm, text = "SEND >", command=self.send_message)
		
		# We create our label to notify the user where to expect the messages from the other user. 
		self.mlabel = ttk.Label(self.frm, text="\nReceived messages appear here: \n")
		
		# We create a second label that tells the user where to type messages 
		self.mlabel_second = ttk.Label(self.frm, text="Type your message here: ")
		
		
		# Now we place the widgets on the upper frame. 
		self.mlabel.grid(row=0, column=0)
		self.mtext_widget.grid(row=1, column=0, sticky=tk.EW)
		self.mscroll_bar.grid(row=1, column=1, sticky=tk.NS)
		self.mlabel_second.grid(row=2, column=0)
		self.mentry_widget.grid(row=3, column=0, sticky=tk.EW)
		self.msend_button.grid(row=3, column=1, sticky=tk.NS)
		
			
			
    # Function that deals with sending of message to the other users. 
	def send_message(self):
		# The user types the message into the testbox in the format: @username: Message format. 
		# First we get the contents from the text field. 
		message = self.message_var.get().strip('@ ')
		
		# Since the user submits the message in the format 
		# @user: My Message!
		# We need to extract the username and message from that. 
		tokens = message.split(":")
		
		# If we dont have the sufficient number of tokens the message is ignored and not sent. 
		if len(tokens) < 2:
			messagebox.showinfo(title="SecureP2P client", message="Please type messages to send in the format\n as shown in this example: \n\n@example_other_username: My message to sent! \n\nPress the 'SEND >' button to send the message to the client ! ")
			return
			
		# Sending messages to self is not allowed. 
		if tokens[0] == self.username.get():
			messagebox.showerror(title="SecureP2P client", message="Sending messages to your self is not allowed !")
			return 
			
		# We need to join extra tokens since we need to split only the username and message apart.
		tokens[1] = ":".join(tokens[1:])
	
		# Before we even try to send the message to the desired username we attempt to establish a shared secret key between us and the user referenced by the username we are intending to communicate.        
		mutex_lock.acquire()
		if len(self.shared_secret_user) == 0:
			
			self.insert_to_text_widget(self.text_widget, tk.END, "\n===== ESTABLISHING SHARED SECRET WITH OTHER CLIENT APPS VIA ECDH ===== \n")
			   
			# We have not established the key yet!
			# We generate the public key & private key
			
			self.our_public_key, self.our_private_key = generate_ecdh_keys()
			# We tell the other client that we want to perform ECDH
			response = "MESSAGE:".encode("utf-8") + base64.b64encode(tokens[0].encode("utf-8")) + b":" + base64.b64encode(self.username.get().encode("utf-8")) + b":" + b"ECDH:" + self.our_public_key
			
			# We print the response as plaintext. 
			self.insert_to_text_widget(self.text_widget, tk.END, f"[*] Request to perform ECDH (as plaintext): {response}\n")
			   
			
			
			# We encrypt the above response with AES in counter mode using the shared secret we established with the server since the communication with server is encrypted. 
			response = self.enc.update(response)
			
			# We print the ciphertext as well. 
			self.insert_to_text_widget(self.text_widget, tk.END, f"[*] Request to perform ECDH (as ciphertext): {response}\n")
			   
	
			# We send the encrypted response to the server. 
			self.serv_sock.send(response)
			
			# We ask the user to wait till ECDH completes & then try sending the message again. 
			messagebox.showinfo(title="SecureP2P client", message=f"Establishing shared secret with user '{tokens[0]}' via ECDH using our public key: {self.our_public_key}\nPlease wait for confirmation ! \n")
			
			mutex_lock.release()
			return
			
		mutex_lock.release()
			
			
		# We check to see if the shared secret we established with the other user (using the client app) expired or not.
		mutex_lock.acquire()
		if int(time.time() - self.creation_time_ssu) > EXPIRY_TIME:
			# We notify the user that the shared secret we established with the other user has expired and we need to perform ECDH again!
			messagebox.showwarning(title="SecureP2P client", message=f"The shared secret key we established with '{tokens[0]}' has expired !\nPerforming ECDH again to establish a new shared secret !\nPlease wait for confirmation & then try again! ")
			
			# We print similar info into our output text widget as well. 
			self.insert_to_text_widget(self.text_widget, tk.END, "===== SHARED SECRET KEY EXPIRED, NEED TO PERFORM ECDH AGAIN =====\n")
			   
			
			# We reset all the values. 
			self.shared_secret_user = b""
			self.our_public_key = b""
			self.our_private_key = None
			
			# The mutex lock is released. 
			mutex_lock.release()
			
			# We call the function recursively to achieve the desired effect. 
			self.send_message()
			return 
			
		
		if mutex_lock.locked():
			mutex_lock.release()
			
			
		#=============================================#
		# We have established the shared secret key (used for symmetric encryption) for communicating securely with the user
		# whom we are interested in communicating with ! 
		#==============================================# 
		
		# Since we are using Tkinter widgets, we use mutex locks to protect from race conditions. 
		mutex_lock.acquire()
		# We use that shared secret key `self.shared_secret_user` to encrypt the message we got from the entry widget. 
		self.insert_to_text_widget(self.text_widget, tk.END, f"[*] Message we want to send (plaintext form): {tokens[1]}\n")
		   
		message_encrypted = self.enc_ssu.update(tokens[1].encode("utf-8"))
		self.insert_to_text_widget(self.text_widget, tk.END, f"[*] Message we want to send (in ciphertext form): {message_encrypted}\n")
		   
		# The above encrypted message is base64 encoded. 
		message_encrypted = base64.b64encode(message_encrypted)
		
		self.insert_to_text_widget(self.text_widget, tk.END, f"[*] The ciphertext in base64 encoded format: {message_encrypted}\n")
		   
		
		# Now we format the response to the server!
		response = "MESSAGE:".encode("utf-8") + base64.b64encode(tokens[0].encode("utf-8")) + b":" + base64.b64encode(self.username.get().encode("utf-8")) +  b":" + message_encrypted
		
		# The above formatted response is also printed to the output window. 
		self.insert_to_text_widget(self.text_widget, tk.END, f"[*] Message to server as plaintext: {response}\n")
		   
		
		# Since we have already established shared secret with the server the above response needs to be encrypted with the encryption cipher using that shared secret key
		response = self.enc.update(response)
		
		# The resulting ciphertext is printed to the output window. 
		self.insert_to_text_widget(self.text_widget, tk.END, f"[*] Message to server as ciphertext: {response}\n")
		   
		
		# Finally we send the encrypted payload to the server, where the server decrypts it identifies the username & forwards it to the correct client
		self.serv_sock.send(response)
		
		# We clear the message entry widget. 
		self.mentry_widget.delete(0, tk.END)
		
		# We release the mutex lock
		mutex_lock.release()
		
		
	# The function that starts the thread that will monitor incomming messages from the server. 
	# These messages are messages sent by the other client logged in with the server. 
	def start_monitoring_thread(self):
		self.run = True
		self.thread = Thread(target=self._monitoring_thread)
		self.thread.start()
		
		
	 # The function that runs as a thread function receiving messages from the other user through the central server. 
	def _monitoring_thread(self):
	   print("[~] Receiver thread started !")
	   
	   while True:
	   	# First we check if we are allowed to run. 
	   	mutex_lock.acquire()
	   	can_run = self.run
	   	mutex_lock.release()
	   	
	   	if not can_run:
	   		break
	   		
	   	# We receive the response from the central server. 
	   	response = self.serv_sock.recv(MAX_SIZE)
	   	
	   	if len(response) == 0:
	   		# If we couldn't receive any response from the server we can break the loop. 
	   		break
	   		
	   	mutex_lock.acquire()
	   	self.insert_to_text_widget(self.text_widget, tk.END, f"[~] Response we got from the server: {response}\n")
	   	   
	   	mutex_lock.release()
	   		
	   	# Since we received the response from the central server
	   	# we must decrypt it using the shared key we already established with it. 
	   	response = self.dec.update(response)
	   	
	   	
	   	mutex_lock.acquire()
	   	self.insert_to_text_widget(self.text_widget, tk.END, f"[~] Decrypted response from the server: {response}\n")
	   	   
	   	mutex_lock.release()
	   	
	   	# We tokenize the response buffer. 
	   	response = response.decode("utf-8")
	   	tokens = response.split(":")
	        
	   	if tokens[0] == "MESSAGE":
	   		# This is good, because we got a message from another user through our server ! 
	   		# We decode the username of the interested client.
	   		decoded_username = base64.b64decode(tokens[2].encode("utf-8")).decode("utf-8")
	   		
	   		# Next we examine tokens[3]. 
	   		if tokens[3] == "ECDH":
	   			
	   			# if tokens[3] is exactly "ECDH", then that means another client has sent us their public key (in tokens[4]) for establishing a shared secret. 
	   			# First we need to verify if we have sent them our public key. 
	   			mutex_lock.acquire()
	   			flag = (self.our_public_key != b"")
	   			mutex_lock.release()
	   		
	   			if not flag:
	   				# We have NOT sent the other user our public key yet! 
	   				# OR the public key we had expired.
	   				# So we generate new public, private key pair, send the new public key to the client via central server and then establish shared secret!
	   				mutex_lock.acquire()
	   			
	   				# We generate the new public & private key. 
	   				self.our_public_key, self.our_private_key = generate_ecdh_keys()
	   				# We tell the other client that we want to perform ECDH
	   				response = "MESSAGE:".encode("utf-8") + tokens[2].encode("utf-8") + b":"  + base64.b64encode(self.username.get().encode("utf-8")) + b":" + b"ECDH:" + self.our_public_key
	   				
	   				# We print the response as plaintext. 
	   				self.insert_to_text_widget(self.text_widget, tk.END, f"[*] Request to perform ECDH (as plaintext): {response}\n")
	   				   
	   			
	   				# We encrypt the above response with AES in counter mode using the shared secret we established with the server since the communication with server is encrypted. 
	   				response = self.enc.update(response)
	   				# We print the ciphertext as well. 
	   				self.insert_to_text_widget(self.text_widget, tk.END, f"[*] Request to perform ECDH (as ciphertext): {response}\n")
	   				   
	   				# We send the encrypted response to the server. 
	   				self.serv_sock.send(response)
	   				# We ask the user to wait till ECDH completes & then try sending the message again. 
	   			
	   				messagebox.showinfo(title="SecureP2P client", message=f"Establishing shared secret with user '{decoded_username}' via ECDH using our public key: {self.our_public_key}.\nPlease wait for confirmation ! \n")
			
	   				mutex_lock.release()
	   				
	   			#======================================#
	   			# We can establish the shared secret now.
	   			# We have sent them a public key & we can establish shared secret key with our private key we already generated.
	   			mutex_lock.acquire()
	   			
	   			# The public key of the client interested in communicating is the 5th token (index = 4)
	   			client_public_key = tokens[4]
	   			
	   			# We print the client's public key in our text box. 
	   			self.insert_to_text_widget(self.mtext_widget, tk.END, f"{decoded_username}'s public key: {client_public_key}\n")
	   			
	   			self.shared_secret_user = establish_shared_secret_ecdh(client_public_key.encode("utf-8"), self.our_private_key)
	   			# We create the AES CTR cipher!
	   			self.cipher_ssu = Cipher(algorithms.AES(self.shared_secret_user), modes.CTR(b"\x00"*16))
	   			# We instantiate the encryptor & decryptor objects using the cipher object.
	   			self.enc_ssu = self.cipher_ssu.encryptor()
	   			self.dec_ssu = self.cipher_ssu.decryptor()
	   			self.creation_time_ssu = time.time()
	   			
	   			self.insert_to_text_widget(self.mtext_widget, tk.END, f"[Shared secret key (AES 256 bit)]: {self.shared_secret_user}\n")
	   			
	   			# Once the shared secret is established we discard the public key. 
	   			self.our_public_key = b""
	   			mutex_lock.release()
	   			#
	   			messagebox.showinfo(title="SecureP2P client", message=f"Shared secret key established: {self.shared_secret_user}")
	   				
	   		else:
	   			# tokens[3] is the base64 encoded encrypted message that is encrypted using the shared secret key established with the client app. 
	   			ciphertext = tokens[3].encode("utf-8")
	   			
	   			mutex_lock.acquire()
	   			self.insert_to_text_widget(self.mtext_widget, tk.END, f"{decoded_username}'s message (base64 encoded ciphertext): {ciphertext}\n")
	   			ciphertext = base64.b64decode(ciphertext)
	   			self.insert_to_text_widget(self.mtext_widget, tk.END, f"{decoded_username}'s message (base64 decoded ciphertext): {ciphertext}\n")
	   			# Finally we decrypt the message. 
	   			decrypted = self.dec_ssu.update(ciphertext)
	   			self.insert_to_text_widget(self.mtext_widget, tk.END, ("%s's message (decrypted): %s\n") % (decoded_username, decrypted.decode("utf-8")))
	   			mutex_lock.release()
	   			
	   			
	   			
	   			
	   		
	   	else:
	   		# We show a message box stating that a particular username is offline!
	   		mutex_lock.acquire()
	   		decoded_username = base64.b64decode(tokens[0].encode("utf-8")).decode("utf-8")
	   		self.insert_to_text_widget(self.mtext_widget, tk.END, ("%s: %s\n")%(decoded_username, tokens[1]))
	   		messagebox.showerror(title="SecureP2P client", message=tokens[1])
	   		mutex_lock.release()
	   		
	   		
	   # The thread has completed its job. 
	   print("[~] Message receiving thread is returning... ")
	  
			
	# Function to be called when window gets closed. 	
	def on_closing(self):
		self.root.destroy()
		
	# Helper function that inserts texts to Tkinter widgets. 
	def insert_to_text_widget(self, t, pos, content):
		t.insert(pos, content)
		
		

# Main entry point of our application. 
def main():
	print("\t   * CLIENT APP *\n")
	
	# We start our client application. 
	app = ClientAPP(SERVER_IP, PORT)
	
	return 0
	
	


if __name__ == "__main__":
	main()


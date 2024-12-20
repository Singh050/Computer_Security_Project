**SecureP2P Communication System**

A **Secure Peer-to-Peer (P2P) Communication System** with a central server that provides **end-to-end encrypted communication** using state-of-the-art cryptographic techniques.

---

📜 **Overview**

This project implements a secure chat system with a focus on privacy and data integrity:
- **Client Application:** Built with Python and a Tkinter-based GUI.
- **Central Server:** Facilitates encrypted communication between users.
- **Encryption Features:**
  - **Elliptic Curve Cryptography (ECC):** For secure key exchange.
  - **AES-256 CTR Mode:** For symmetric encryption of messages.
  - **SHA-256:** Ensures a fixed 256-bit shared secret for maximum security.

---

✨ **Key Features**

1. **Double-Layer Encryption**
   - **First Layer:** Communication between clients and the server is encrypted using AES-256.
   - **Second Layer:** End-to-end encryption between users ensures that even the server cannot read user messages.

2. **User Authentication**
   - User credentials are securely hashed with **SHA-256** before being stored on the server.
   - Login and registration data are encrypted using the shared secret key established via ECC.

3. **Dynamic Key Generation**
   - ECC-based **Elliptic Curve Diffie-Hellman (ECDH)** generates ephemeral keys for secure communication.
   - Ensures fresh shared secrets for each session.

4. **Multi-Threaded Server**
   - Handles multiple client connections simultaneously.
   - Relays messages securely without accessing plaintext content.

5. **GUI for User Interaction**
   - Simple registration and login interface.
   - Messaging interface with real-time updates and cryptographic details displayed for transparency.

---

🛠️ **Tools and Technologies**

- **Programming Language:** Python
- **GUI Framework:** Tkinter
- **Cryptography:** ECC (SECP256k1), AES-256 CTR Mode
- **Libraries Used:** `cryptography`, `hashlib`, `socket`, `base64`
- **Operating System:** Linux/Windows

---

🔧 **How to Run the Project**

Prerequisites
1. Install Python (v3.8 or later).
2. Install dependencies:
   ```bash
   pip install cryptography


**Steps**

1. **Start the Server**
   > Navigate to the project directory and run:-
   
   > python central_server.py
   
   > The server will initialize and wait for incoming client connections. 

2. **Start the Client**
   > Open a new terminal and run:-
   
   > python clientapp.py
   
   > The GUI for the client application will launch.
   
3. **Register or Login**
   > Use the GUI to register a new user or login with existing credentials.
   
4. **Send and Receive Messages**
   > Logged-in users can securely exchange messages by specifying the recipient's username in the format:
   
   > @recipient_username: Message text here


📊 **Implementation Details**

Security Features
- **Elliptic Curve Diffie-Hellman (ECDH):**
  - Establishes shared secret keys for symmetric encryption.
  - Uses the SECP256k1 curve, trusted for its use in blockchain technologies like Bitcoin.
- **AES-256 CTR Mode:**
  - Encrypts communication between clients and between clients and the server.
  - Ensures that ciphertext length matches plaintext length without padding.
- **End-to-End Encryption:**
  - Messages between users are encrypted with a shared secret key unknown to the server.

Multi-Threaded Server
- Handles multiple clients concurrently using Python's `threading` module.
- Each thread manages communication for one client, ensuring scalability.

GUI Features
- User-friendly interface for registration, login, and messaging.
- Displays cryptographic details (e.g., public keys, ciphertexts) for transparency.

---

📈 **System Architecture**

1. **Client-Server Communication:**
   - Each client establishes a shared secret key with the server for secure interactions.
2. **Peer-to-Peer Communication:**
   - Clients exchange public keys via the server and establish a direct shared secret key for end-to-end encryption.

---

🔒 **Security Highlights**

- **Data Integrity:** Prevents tampering using cryptographic hashing.
- **Privacy:** Server cannot decrypt user messages due to end-to-end encryption.
- **Dynamic Keys:** Ensures no static keys are reused, protecting against key compromise.

---

📬 **Contact**

For any queries or collaboration, reach out to:  
**Barjinder Singh** - [barjindersingh@ou.edu](mailto:barjindersingh@ou.edu)




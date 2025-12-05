# Secure Mobile Messenger – ICS344 Project

Course: ICS344 – Information Security
Bucket / Group: P26 – AES-CBC (PKCS#7) + RSA Digital Signatures
Platform: Mobile-based using Python Kivy

------------------------------------------------------------

1. Overview

This project implements a mobile-style secure messaging prototype.

- Confidentiality: AES-256 in CBC mode with PKCS#7 padding
- Integrity and authenticity: RSA-2048 digital signatures (RSA-PSS with SHA-256)
- UI: Mobile-based GUI built with Python Kivy (as requested in the project handout)

The app simulates a sender, a receiver, and an attacker who can modify the JSON packet on the “network”. It demonstrates normal secure communication and four attacks, along with their mitigations.

------------------------------------------------------------

2. Features

- Compose plaintext messages and send them securely.

Packet format (JSON) conceptually contains:
- iv: base64 IV
- ciphertext: base64 AES-CBC ciphertext
- signature: base64 RSA-PSS signature over (iv || ciphertext)
- sender_public_key: base64 PEM of the sender public key

Receiver:
- Verifies RSA signature using a pinned sender public key.
- Detects and blocks replayed packets.
- Detects and blocks IV/nonce reuse.
- Decrypts and displays the recovered plaintext.

Attacker / Debug Panel (for demo only):
- Tamper – modifies ciphertext in the packet (message injection).
- Replay – resends the last valid packet.
- MITM Key – key-substitution attack (attacker re-signs with their own RSA key).
- IV Reuse – reuses the same IV with the same AES key (nonce reuse / key exhaustion).

------------------------------------------------------------

3. Security and Mitigations

Message Injection:
- The sender signs (iv || ciphertext) using RSA-PSS.
- Any modification of IV or ciphertext causes signature verification to fail, so the receiver rejects the packet.

Replay Attack:
- The receiver keeps a set of previously accepted packets (seen_packets).
- If exactly the same packet appears again, the receiver logs “Replay detected” and drops it.

MITM Key Substitution:
- The receiver ignores the sender_public_key value inside the JSON packet.
- It always verifies signatures using the trusted pinned sender public key generated at startup.
- If an attacker replaces the key and signature, verification fails and the packet is dropped.

IV / Nonce Reuse (Key Exhaustion):
- The receiver tracks all IVs used with this AES key (seen_ivs).
- If an IV is reused, the receiver treats it as a nonce-reuse / key-exhaustion attack, logs “IV reuse detected”, and rejects the packet.

------------------------------------------------------------

4. Setup

Tested with Python 3.11 on Windows.

4.1 Create and activate virtual environment (Windows):

- python -m venv venv
- venv\Scripts\activate

4.2 Install dependencies using requirements.txt:

- pip install -r requirements.txt

requirements.txt should contain:
- cryptography
- kivy[base]

Or manually:
- pip install cryptography "kivy[base]"

------------------------------------------------------------

5. Running the App

From the project folder with the virtual environment activated:

- python main.py

This starts the Kivy mobile-style app.

------------------------------------------------------------

6. How to Use

6.1 Normal secure message

- Type a message in the bottom input box (compose area).
- Click “Send Securely”:
  - AES-CBC encrypts the message and RSA signs (iv || ciphertext).
  - A JSON packet appears in the Encrypted Packet (network view) area.
- Click “Receive / Verify”:
  - The receiver verifies the RSA signature with the pinned sender key.
  - Checks replay and IV reuse.
  - Decrypts the ciphertext if everything is valid.
  - Plaintext appears in Received (receiver view) and the security log shows success.

6.2 Tamper (Message Injection)

- After sending a message, click “Tamper” in the Attacker / Debug Panel (this flips some bits in the ciphertext field).
- Click “Receive / Verify”.
- The log shows that signature verification failed (using the pinned key), so the tampered packet is rejected and no new plaintext is displayed.

6.3 Replay Attack

- Send and verify at least one valid message.
- Click “Replay” in the attacker panel to resend the last packet.
- The receiver sees that the same packet was already accepted (seen_packets) and logs “Replay detected”, dropping the packet (no new message appears in the receiver view).

6.4 MITM Key-Substitution Attack

- After having a valid packet in the network area, click “MITM Key”.
  The attacker re-signs the packet using their own RSA key and replaces sender_public_key.
- Click “Receive / Verify”.
- Because the receiver uses a pinned real key instead of the packet’s key, signature verification fails and the log reports a possible MITM attack. The packet is rejected.

6.5 IV Reuse (Nonce Reuse / Key Exhaustion)

- Send and verify one honest message.
- Change the plaintext in the input box and click “IV Reuse”.
  This creates a new packet that reuses the previous IV with the same AES key.
- The security log shows:
  - The reused IV value (base64).
  - The first ciphertext block of both messages and whether they are equal.
- When you click “Receive / Verify”, the receiver detects that the IV was already used (seen_ivs) and logs “IV reuse detected”, dropping the packet.

------------------------------------------------------------

7. Files

aes_cbc.py
- AES key generation (AES-256)
- AES-CBC encrypt/decrypt
- PKCS#7 padding helpers

rsa_sign.py
- RSA-2048 key generation
- RSA-PSS sign / verify with SHA-256
- PEM export/import of public keys

secure_message_demo.py
- Command-line helper demo that builds a secure packet and processes it using the crypto functions

main.py
- Kivy mobile GUI
- Sender / receiver flow
- Attacker / debug panel (Tamper, Replay, MITM Key, IV Reuse)
- Replay detection, MITM protection (key pinning), and IV reuse detection

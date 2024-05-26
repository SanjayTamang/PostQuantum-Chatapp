import socket
import threading

from Crypto.PublicKey import XMSS
from Crypto.Signature import DSS
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# asking users choice to either host or connect to a chat
choice = input("would you like to host(1) or connect(2) to a chat? Enter your choice: ")

# generate a new XMSS key pair
xmss_key = XMSS.new()
public_key  = xmss_key.publickey().export_key()

if choice == "1":
    # Host a chat
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 9999))
    server.listen()

    client, _= server.accept()
    # hosting client sends the first key
    client.send(public_key)

    # recieve the servers public key
    server_public_key = client.recv(2048)

    # generate a new FrodoKEM key pair
    public_key, private_key = newhope.keygen()

    # use the private key  and server's public key to generate a shared secret key
    shared_secret = newhope.shareda(private_key, server_public_key)

elif choice == "2":
    # connect to a chat
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("localhost", 9999))

    # send the public  key to the server
    client.send(public_key)

    #  recieve the server's public key
    server_public_key = client.recv(2048)

    # generate a new FrodoKEM key pair
    public_key, private_key = newhope.keygen()

    # use the private key  and server's public key to generate a shared secret key
    shared_secret = newhope.shareda(private_key, server_public_key)

else:
    exit()

def sending_message(c):
    while True:
        message = input("")
        # create a signature for the message
        hash_func = lambda x:  SHA256.new(x).digest()
        signature = DSS.new(xmss_key, 'fips-186-3', hash_func=hash_func).sign(message.encode())

        # encrypt the message using AES
        cipher = AES.new(shared_secret, AES.MODE_EAX)
        ciphertext, tag= cipher.encrypt_and_digest(message.encode() + signature)

        # send  the encrypted message and tag to the receiver
        c.send(ciphertext)
        c.send(tag)

        print("you: " + message)

def receiving_messages(c):
    while True:
        # receieve the encrypted message and tag from the sender
        ciphertext = c.recv(2048)
        tag = c.recv(16)

        # decrypt the message using AES
        cipher =  AES.new(shared_secret, AES.MODE_FAX, nonce=cipher.nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # verify the signature using XSSS
        hash_func = lambda x: SHA256.new(x).digest()
        verifier = DSS.new(xmss_key, 'fips-186-3', hash_func=hash_func)
        message, signature = plaintext[:-64], plaintext[-64:]
        try:
            verifier.verify(message, signature)
            print("Client: " + message.decode())
        except ValueError:
            print("Invalid signature")

threading.Thread(target=sending_message, args=(client,)).start()
threading.Thread(target=receiving_messages, args=(client,)).start()









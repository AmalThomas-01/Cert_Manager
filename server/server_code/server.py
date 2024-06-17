import socket
import ssl
import threading
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def is_certificate_revoked():
    issuer_file = '../MyPKISubCAG1.pem'
    cafile = '../MyPKISubCAG1-chain.pem'
    cert_file = 'certificates.pem'
    ocsp_url = 'http://localhost/ejbca/publicweb/status/ocsp'

    # Construct the openssl command
    openssl_command = [
    	'openssl',
    	'ocsp',
    	'-issuer', issuer_file,
    	'-CAfile', cafile,
    	'-cert', cert_file,
    	'-req_text',
    	'-url', ocsp_url
	]

    # Run the openssl command using subprocess
    result = subprocess.run(openssl_command, stdout=subprocess.PIPE, text=True)
    #print(result)

    # Print the result
    status_lines = [line.strip() for line in result.stdout.split('\n') if line.strip().endswith(": good")]

    return status_lines

		

def handle_client(secure_sock, from_addr):
    try:
        cert = secure_sock.getpeercert(binary_form=True)
        print("\n Client certificate\n")
        cert_print = secure_sock.getpeercert()
        print(cert_print)
        
        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
        pem_cert = x509_cert.public_bytes(encoding=serialization.Encoding.PEM)
        output_cert = "certificates.pem"
        out_file = open(output_cert, "wb")
        out_file.write(pem_cert)
        out_file.close()
        if not is_certificate_revoked():
                print("Client certificate is revoked....\n")
                secure_sock.send(b"Certificate not Valid")
                print("Connection terminated.........")
                return
        print("Connection is established\n")		

        
        data = secure_sock.recv(1024)
        print("Message received")
        msg=data.decode('utf-8') 
        print (msg)
        secure_sock.send(data)
    except ssl.SSLError as e:
        print(f"SSL Handshake Error for {from_addr}: {e}")
    finally:
        secure_sock.close()
        print(f"Connection with {from_addr} closed.")

def accept_connections(server_socket, context):
    while True:
        new_socket, from_addr = server_socket.accept()
        secure_socket = context.wrap_socket(new_socket, server_side=True)

        # Start a new thread to handle the client
        print("\nA new client is connected.....................")
        client_handler = threading.Thread(target=handle_client, args=(secure_socket, from_addr))
        client_handler.start()

def start_server():
    HOST = 'localhost'
    PORT = 8080

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Set verification options as needed
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations('../MyPKISubCAG1-chain.pem')
    context.load_cert_chain(certfile="servercert.pem", keyfile="server.key")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    # Start a thread to accept connections in the background
    accept_thread = threading.Thread(target=accept_connections, args=(server_socket, context))
    accept_thread.start()

    # The main thread can continue to do other tasks if needed
    print("Server is running. Press Ctrl+C to exit.\n")

    try:
        accept_thread.join()  # Wait for the accept thread to finish if needed
    except KeyboardInterrupt:
        print("Server shutting down.........")
    finally:
        server_socket.close()

def connect():
    start_server()


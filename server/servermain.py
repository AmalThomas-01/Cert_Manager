import socket
import ssl
import threading
import subprocess
import requests

def crl_check(target_serial_number):
    url = "http://localhost/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DMy+PKI+Sub+CA-G1%2CO%3DKeyfactor+Community%2CC%3DSE"
    try:
        response = requests.get(url)

        if response.status_code == 200:
            # Download and save the CRL
            with open("CA.crl", "wb") as crl_file:
                crl_file.write(response.content)
            print("Successfully downloaded CRL as CA.crl")
        else:
            # Handle error
            print("API call failed with status code:", response.status_code)

    except requests.exceptions.RequestException as e:
        # Handle network errors
        print("An error occurred:", e)

    crl_file = "CA.crl"

    # Execute the OpenSSL command and capture output line by line
    crl_info = subprocess.Popen(["openssl", "crl", "-in", crl_file, "-text"], stdout=subprocess.PIPE, universal_newlines=True)

    # Wait for the command to finish
   
    for line in crl_info.stdout:
    	print(line, end='')
    	lines = []
    	lines.append(line.strip())
    	if line.startswith("Serial Number:"):
            serial_number = line.split(":")[1].strip()
            print(serial_number)
            if(serial_number == target_serial_number):
                print("Serial number found in CRL!")
                return 1
    crl_info.wait()
    return 0    	       
    


def handle_client(secure_sock, from_addr):
    try:
        cert = secure_sock.getpeercert()
        serial_number = cert['serialNumber']
        if crl_check(serial_number):
            print("connection is terminated........." )		
            return

        print(f'Full cert for {from_addr}: {cert}')

        data = secure_sock.recv(1024)
        print(data)
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
    context.load_verify_locations('MyPKISubCAG1-chain.pem')
    context.load_cert_chain(certfile="4F8493EF610C3F944431DFEDA74C80A04A129681.pem", keyfile="server.key")

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

if __name__ == '__main__':
    start_server()


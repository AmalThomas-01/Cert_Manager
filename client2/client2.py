
import socket
import ssl
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sys

# client
def is_certificate_revoked():
    issuer_file = 'MyPKISubCAG1.pem'
    cafile = 'MyPKISubCAG1-chain.pem'
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

    # Print the result
    status_lines = [line.strip() for line in result.stdout.split('\n') if line.strip().endswith(": good")]

    return status_lines





if __name__ == '__main__':

    HOST = 'localhost'
    PORT = 8080

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(1);
    sock.connect((HOST, PORT))

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False 
    context.load_verify_locations('MyPKISubCAG1-chain.pem')
    context.load_cert_chain(certfile="client2.pem", keyfile="client2.key")

    if ssl.HAS_SNI:
        secure_sock = context.wrap_socket(sock, server_side=False,server_hostname=HOST)
    else:
        secure_sock = context.wrap_socket(sock, server_side=False)

    cert = secure_sock.getpeercert(binary_form=True)
    cert1 = secure_sock.getpeercert()
    
    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
    pem_cert = x509_cert.public_bytes(encoding=serialization.Encoding.PEM)
    output_cert = "certificates.pem"
    out_file = open(output_cert, "wb")
    out_file.write(pem_cert)
    out_file.close()
    if not is_certificate_revoked():
    	secure_sock.send(b"Certificate not Valid")
    	print("Connection terminated.........")
    	sys.quit()

    print("Connection is established")
    value=input("Enter text=")
    try:
    	secure_sock.send(value.encode())
    	data=secure_sock.read(1024)
    	msg=data.decode('utf-8') 
    	print (msg)
    except Exception as e:
    	print("Connection error:", e)
    	print("Connection lost")
    

    secure_sock.close()
    sock.close()


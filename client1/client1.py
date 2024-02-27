
import socket
import ssl
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sys
from crl_checker import check_revoked, Revoked, Error


def crl_checking(cert_pem):
	try:
	    check_revoked(cert_pem)
	except Revoked as e:
	    print(f"Certificate revoked: {e}")
	except Error as e:
	    print(f"Revocation check failed. Error: {e}")
	    raise

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
    context.load_cert_chain(certfile="51690F08190E8784ADEA200D0C946D43BBE91C6D.pem", keyfile="client.key")

    if ssl.HAS_SNI:
        secure_sock = context.wrap_socket(sock, server_side=False,server_hostname=HOST)
    else:
        secure_sock = context.wrap_socket(sock, server_side=False)

    cert = secure_sock.getpeercert(binary_form=True)
    
    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
    pem_cert = x509_cert.public_bytes(encoding=serialization.Encoding.PEM)
    output_cert = "certificates.pem"
    out_file = open(output_cert, "wb")
    out_file.write(pem_cert)
    out_file.close()
    
    pem_cert=pem_cert.decode('utf-8')
    crl_checking(pem_cert)
    if not is_certificate_revoked():
    	print("Server certificate is okay....\n")
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


import socket
import ssl
import pprint

#server
if __name__ == '__main__':

    HOST = 'localhost'
    PORT = 8080


    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# Set verification options as needed
    context.verify_mode = ssl.CERT_REQUIRED
    #context.check_hostname = False 
    context.load_verify_locations('MyPKISubCAG1-chain.pem')
    context.load_cert_chain(certfile="4F8493EF610C3F944431DFEDA74C80A04A129681.pem", keyfile="server.key")



    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

  
                     
    try:
    	newsocket, fromaddr = server_socket.accept()    
    	secure_sock = context.wrap_socket(newsocket, server_side=True)
    	cert = secure_sock.getpeercert()
    	print (f'full cert {cert}')
    except ssl.SSLError as e:
        print(f"SSL Handshake Error: {e}")

    
                       

    #print ('The certificate'+repr(secure_sock.getpeername()))
    #print (f'cipher{secure_sock.cipher()}')
    #print ('peercert'+pprint.pformat(secure_sock.getpeercert()))
    

    # verify client
    #if not cert or ('commonName', 'client.test') not in cert['subject'][3]: raise Exception("ERROR")

    try:
        data = secure_sock.recv(1024)
        secure_sock.send(data)
    finally:
    	secure_sock.close() 
    	server_socket.close()

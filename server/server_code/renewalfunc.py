from ocsp import ocsp_func
from pkscenroll import enrollment

def renewal():
    server_cert="servercert.pem"
    status,reason=ocsp_func(server_cert)

    if status == 'revoked':
        print("Certificate Revoked")
        enrollment(reason)
    else:
        print("Certificate is valid")    
            

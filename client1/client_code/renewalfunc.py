from ocsp import ocsp_func
from pkscenroll import enrollment

def renewal():
    client_cert="clientcert.pem"
    status,reason=ocsp_func(client_cert)

    if status == 'revoked':
        print("Certificate Revoked")
        enrollment(reason)
    else:
        print("Certificate is valid")    
            

#!/usr/bin/python3

import json
import subprocess
import requests
from urllib3.exceptions import InsecureRequestWarning
import getpass
import subprocess

def enrollment(reason):
    def generate_enc_key(key_file):
        openssl_command = ['openssl','genpkey','-algorithm','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-aes256','-out',key_file]

        try:
            subprocess.run(openssl_command, check=True)
            print(f"ECDSA key successfully generated: {key_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error generating ECDSA key: {e}")

    def generate_csr_with_key(key_file, csr_file, config_file):
        password=getpass.getpass("Enter the passphrase:")
        openssl_command = ['openssl', 'req', '-new', '-key', key_file,'-passin','pass:'+password, '-config', config_file, '-out', csr_file]

        try:
            subprocess.run(openssl_command, check=True)
            print(f"CSR successfully generated: {csr_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error generating CSR: {e}")
            subprocess.run(['rm',key_file], check=True)

    def pkcs10enroll(InputCsrFile, caHost, trustChainFile, clientCrt, clientKey, certProfile, eeProfile, caName, userName):
        
        InputCsrFile = InputCsrFile
        caHost = caHost
        trustChainFile = trustChainFile
        clientCrt = clientCrt
        clientKey = clientKey
        certProfile = certProfile
        eeProfile = eeProfile
        caName = caName
        userName = userName

        csr_file = open(InputCsrFile, mode='r')
        csr = csr_file.read()
        csr_file.close()
        
        print(csr)
        
        postURL = 'https://' + caHost + '/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll'
        
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)  
        
        response = requests.post(postURL,
            json={
                "certificate_request": csr,
                "certificate_profile_name": certProfile,
                "end_entity_profile_name": eeProfile,
                "certificate_authority_name": caName,
                "username": userName,
                "password": "fool1234"
            },
            headers={
                'content-type': 'application/json'
            },
            verify=False,
            cert=(clientCrt, clientKey))
        
        print (response.content)
        print(json.dumps(json.loads(response.content), indent=4, sort_keys=True))
        
        json_resp = response.json()
        
        cert = json_resp['certificate']
        
        #reconstruct certificate from json array
        pem = "-----BEGIN CERTIFICATE-----"
        for i in range(len(cert)):
            if i % 64 == 0:
                pem += "\n"
            pem += cert[i]
        
        pem += "\n-----END CERTIFICATE-----"
        
        output_cert = "servercert.pem"
        out_file = open(output_cert, "w")
        out_file.write(pem)
        out_file.close()

    key_file='server.key'
    csr_file='../server.csr'
    config_file='../server.conf'
    
    if reason != 'expired':
        generate_enc_key(key_file)
    generate_csr_with_key(key_file,csr_file,config_file)
    
    InputCsrFile = csr_file
    caHost = 'localhost'
    trustChainFile = '../Chain.pem'
    clientCrt = '../SuperAdmin1.pem'
    clientKey ='../SuperAdmin1.key'
    certProfile = 'TLS Server Profile'
    eeProfile = 'TLS Server Profile'
    caName = 'MyPKISubCA-G1'
    userName = 'server-01'
    
    pkcs10enroll(InputCsrFile, caHost, trustChainFile, clientCrt, clientKey, certProfile, eeProfile, caName, userName)

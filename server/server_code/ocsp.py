import subprocess

def ocsp_func(cert_file):
    issuer_file = '../MyPKISubCAG1.pem'
    cafile = '../MyPKISubCAG1-chain.pem'
    ocsp_url = 'http://localhost/ejbca/publicweb/status/ocsp'
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
    status_lines = [line.strip() for line in result.stdout.split('\n') if line.strip().endswith(": good")]
    
    if status_lines:
        status='good'
    else:
        status='revoked'
    
    reason_line = [line.strip() for line in result.stdout.split('\n') if 'Reason:' in line]
    
    # Check if reason was found
    if reason_line:
        reason = reason_line[0].split(': ')[-1]
    else:
        reason = 'NULL' 
    
    return(status,reason)  


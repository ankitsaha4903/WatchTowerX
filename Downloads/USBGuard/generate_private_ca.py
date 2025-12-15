from OpenSSL import crypto
import random

def generate_private_ca():
    print("Generating Private Root CA...")
    
    # 1. Generate Root CA Key
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 4096)
    
    # 2. Generate Root CA Certificate
    ca_cert = crypto.X509()
    ca_cert.get_subject().C = "US"
    ca_cert.get_subject().ST = "SecureState"
    ca_cert.get_subject().L = "SecureCity"
    ca_cert.get_subject().O = "USB Guard Private CA"
    ca_cert.get_subject().OU = "Security Team"
    ca_cert.get_subject().CN = "USB Guard Root CA"
    
    ca_cert.set_serial_number(random.getrandbits(64))
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60) # Valid for 10 years
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.set_pubkey(ca_key)
    
    # Add Basic Constraints extension (CA:TRUE)
    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])
    
    ca_cert.sign(ca_key, 'sha256')
    
    # Save Root CA
    with open('rootCA.pem', 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
    with open('rootCA.key', 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
        
    print("✅ Root CA generated: rootCA.pem")

    # ---------------------------------------------------------

    print("Generating Server Certificate for 192.168.150.47...")
    
    # 3. Generate Server Key
    server_key = crypto.PKey()
    server_key.generate_key(crypto.TYPE_RSA, 2048)
    
    # 4. Generate Server CSR
    req = crypto.X509Req()
    req.get_subject().C = "US"
    req.get_subject().ST = "SecureState"
    req.get_subject().L = "SecureCity"
    req.get_subject().O = "USB Guard"
    req.get_subject().OU = "Dashboard"
    req.get_subject().CN = "192.168.150.47"
    req.set_pubkey(server_key)
    req.sign(server_key, 'sha256')
    
    # 5. Sign Server Cert with Root CA
    server_cert = crypto.X509()
    server_cert.set_serial_number(random.getrandbits(64))
    server_cert.gmtime_adj_notBefore(0)
    server_cert.gmtime_adj_notAfter(2 * 365 * 24 * 60 * 60) # Valid for 2 years
    server_cert.set_issuer(ca_cert.get_subject())
    server_cert.set_subject(req.get_subject())
    server_cert.set_pubkey(req.get_pubkey())
    
    # Add Extensions (SAN is critical for Chrome/Android)
    server_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
        crypto.X509Extension(b"subjectAltName", False, b"IP:192.168.150.47"),
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
    ])
    
    server_cert.sign(ca_key, 'sha256')
    
    # Save Server Cert
    with open('server.pem', 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))
    with open('server.key', 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key))
        
    print("✅ Server Certificate generated: server.pem, server.key")
    print("\nSUCCESS! To get the Green Lock:")
    print("1. Install 'rootCA.pem' on your devices as a Trusted Root Certificate.")
    print("2. Restart the dashboard using 'server.pem' and 'server.key'.")

if __name__ == "__main__":
    generate_private_ca()

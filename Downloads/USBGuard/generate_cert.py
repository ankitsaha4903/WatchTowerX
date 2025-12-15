from OpenSSL import crypto

# Generate key
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 2048)

# Generate certificate
cert = crypto.X509()
cert.get_subject().C = "US"
cert.get_subject().ST = "State"
cert.get_subject().L = "City"
cert.get_subject().O = "USB Guard"
cert.get_subject().OU = "Security"
cert.get_subject().CN = "192.168.150.47"

cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
cert.set_issuer(cert.get_subject())
cert.set_pubkey(k)
cert.sign(k, 'sha256')

# Save certificate
with open('cert.pem', 'wb') as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

# Save private key
with open('key.pem', 'wb') as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

print("SSL certificates generated successfully!")
print("cert.pem and key.pem created in current directory")

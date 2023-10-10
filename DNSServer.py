import dns.message
import dns.rdatatype
import dns.rdataclass
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key
    
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data    

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# Prepare Encryption Parameters
salt = b'Tandon'  # Remember it should be a byte-object
password = 'af4640@nyu.edu'
secret_data = 'AlwaysWatching'

# Create a dictionary containing DNS records
dns_records = {
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: encrypt_with_aes(secret_data, password, salt),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.SOA: (
            'ns1.example.com.', #mname
            'admin.example.com.', #rname
            2023081401, #serial
            3600, #refresh
            1800, #retry
            604800, #expire
            86400, #minimum
        ),
    },
}

def run_dns_server():
    # Create a UDP socket and bind it to the local IP address and port (the standard port for DNS)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))  # Bind to localhost and port 53 (standard DNS port)

    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)
            # Parse the request using the `dns.message.from_wire` method
            request = dns.message.from_wire(data)
            # Create a response message using the `dns.message.make_response` method
            response = dns.message.make_response(request)

            # Get the question from the request
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if there is a record in the `dns_records` dictionary that matches the question
            if qname in dns_records and qtype in dns_records[qname]:
                # Retrieve the data for the record
                answer_data = dns_records[qname][qtype]

                # Decrypt the data if it is encrypted
                if isinstance(answer_data, bytes):
                    decrypted_data = decrypt_with_aes(answer_data, password, salt)
                else:
                    decrypted_data = answer_data

                # Create an appropriate `rdata` object for the decrypted data
                rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, decrypted_data)]

                for rdata in rdata_list:
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

            # Set the AA (Authoritative Answer) flag manually
            response.flags |= 1 << 10

            # Send the response back to the client using the `server_socket.sendto` method
            server_socket.sendto(response.to_wire(), addr)
            print("Responding to request:", qname)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

if __name__ == '__main__':
    run_dns_server()

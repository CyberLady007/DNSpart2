import dns.message
import dns.rdatatype
from dns.rdataclass import IN
from dns.rdata import from_text as rdata_from_text
from dns.rrset import RRset
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.ANY.A
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

# Function to generate AES key
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

# Function to encrypt data with AES
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data

# Function to decrypt data with AES
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
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: encrypt_with_aes(secret_data, password, salt),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    }
    # Add other DNS records as needed
}

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)
                elif qname == 'nyu.edu.' and qtype == dns.rdatatype.TXT:
                    encrypted_data = dns_records['nyu.edu.'][dns.rdatatype.TXT]
                    decrypted_data = decrypt_with_aes(encrypted_data, password, salt)
                    txt_record = rdata_from_text(IN, dns.rdatatype.TXT, decrypted_data)
                    rdata_list.append(txt_record)
                else:
                    if isinstance(answer_data, str):
                        rdata_list = [rdata_from_text(IN, qtype, answer_data)]

                for rdata in rdata_list:
                    response.answer.append(RRset(question.name, IN, qtype))
                    response.answer[-1].add(rdata)

                response.flags |= 1 << 10
                server_socket.sendto(response.to_wire(), addr)
                print("Responding to request:", qname)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            break

if __name__ == '__main__':
    run_dns_server()

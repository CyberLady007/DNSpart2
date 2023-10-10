import dns.message
import dns.rdatatype
import dns.rdataclass
from dns.rdtypes.ANY.MX import MX
from dns.rdataclass import IN
from dns.rdatatype import MX, SOA, A, AAAA, CNAME, TXT, NS
import dns.rdata
import socket
import threading
import signal
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Decrypt error! Type: {type(e)} Value: {e}")
        return None

salt = b'Tandon'
password = 'af4640@nyu.edu'
secret_data = 'AlwaysWatching'

dns_records = {
    'safebank.com.': { A: '192.168.1.102' },
    'google.com.': { A: '192.168.1.103' },
    'legitsite.com.': { A: '192.168.1.104' },
    'yahoo.com.': { A: '192.168.1.105' },
    'nyu.edu.': {
        A: '192.168.1.106',
        TXT: encrypt_with_aes(secret_data, password, salt),
        MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        NS: 'ns1.nyu.edu.'
    },
    'example.com.': {
        A: '192.168.1.101',
        AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        MX: [(10, 'mail.example.com.')],
        CNAME: 'www.example.com.',
        NS: 'ns.example.com.',
        TXT: ('This is a TXT record',),
        SOA: (
            'ns1.example.com.',  # mname
            'admin.example.com.',  # rname
            2023081401,  # serial
            3600,  # refresh
            1800,  # retry
            604800,  # expire
            86400,  # minimum
        ),
    },
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

                if qtype == MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(IN, MX, pref, server))
                elif qtype == SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(IN, SOA, mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)
                elif qtype == A or qtype == AAAA or qtype == CNAME or qtype == TXT or qtype == NS:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(IN, qtype, answer_data)]
                    elif isinstance(answer_data, bytes):
                        decrypted_data = decrypt_with_aes(answer_data, password, salt)
                        rdata_list = [dns.rdata.from_text(IN, qtype, decrypted_data)]
                    elif isinstance(answer_data, tuple) and qtype == MX:
                        rdata_list = [MX(IN, MX, *answer_data)]
                    else:
                        print(f"Unexpected data type in answer_data: {answer_data}")
                        raise ValueError("Unexpected data type in answer_data")

                for rdata in rdata_list:
                    response.answer.append(dns.rrset.RRset(question.name, IN, qtype))
                    response.answer[-1].add(rdata)

            response.flags |= 1 << 10
            server_socket.sendto(response.to_wire(), addr)
            print("Responding to request:", qname)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

if __name__ == '__main__':
    run_dns_server()

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

# Define Encryption and Decryption Functions:

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

# Encryption parameters

salt = b'Tandon'  # Encode the salt as a byte-object
password = 'af4640@nyu.edu'
input_string = "AlwaysWatching"

# Test encryption and decryption

encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)

# Dictionary containing DNS records

dns_records = {
    'safebank.com.': '192.168.1.102',
    'google.com.': '192.168.1.103',
    'legitsite.com.': '192.168.1.104',
    'yahoo.com.': '192.168.1.105',
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: encrypted_value,  # Use the encrypted data here
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.'
    },
}

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('localhost', 53))  # Bind to localhost and DNS port (53)

def run_dns_server():
    while True:
        try:
            # Wait for incoming DNS requests
            data, addr = server_socket.recvfrom(1024)

            # Parse the request using the `dns.message.from_wire` method
            request = dns.message.from_wire(data)

            # Create a response message using the `dns.message.make_response` method
            response = dns.message.make_response(request)

            # Get the first question from the request
            if not request.question:
                continue  # Ignore invalid queries with no questions
            
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            # Check if there is a record in the `dns_records` dictionary that matches the question
            if qname in dns_records and qtype in dns_records[qname]:
                # Retrieve the data for the record and create an appropriate `rdata` object for it
                answer_data = dns_records[qname][qtype]

                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(
                        dns.rdataclass.IN,
                        dns.rdatatype.SOA,
                        mname, rname, serial, refresh, retry, expire, minimum
                    )
                    rdata_list.append(rdata)
                else:
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]
                
                for rdata in rdata_list:
                    response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                    response.answer[-1].add(rdata)

                # Set the AA (Authoritative Answer) flag manually
                response.flags |= dns.flags.AA

            else:
                # Handle queries for hostnames not in the DNS records with an appropriate error response
                response.set_rcode(dns.rcode.NXDOMAIN)

            # Send the response back to the client
            server_socket.sendto(response.to_wire(), addr)
            print("Responding to request:", qname)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            print("An error occurred:", str(e))

# Handle DNS query timeouts and exceptions in the DNS server thread
try:
    run_dns_server()
except Exception as e:
    print("Exception in DNS server thread:", str(e))

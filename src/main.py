# -*- coding: utf8 -*-
import socket
import time
import zlib
import struct
import logging
import logging.handlers
import rsa
from Crypto.Hash import SHA
from Crypto.Random import random
from aes_ige import AES_IGE

def Int(size=32):
    assert(size % 8 == 0)
    size //= 8
    class int_cl:
        @classmethod
        def Parse(cls, data, offset):
            return (int.from_bytes(data[offset:offset+size], 'little'), size)
        @classmethod
        def Dump(cls, value):
            return value.to_bytes(size, 'little')
    return int_cl

class Long(Int(64)):
    pass

class String:
    @classmethod
    def Parse(cls, data, offset):
        ln = int.from_bytes(data[offset:offset+1], 'little')
        if ln == 254:
            ln = int.from_bytes(data[offset+1:offset+4], 'little')
            return (data[offset+4:offset+4+ln], (((ln+4)-1)//4+1)*4)
        else:
            return (data[offset+1:offset+1+ln], (((ln+1)-1)//4+1)*4)
    @classmethod
    def Dump(cls, value):
        if len(value) <= 253:
            return len(value).to_bytes(1, 'little') + value + b'\0' * (3 - len(value) % 4)
        return b'\xfe' + len(value).to_bytes(3, 'little') + value + b'\0' * (3 - (len(value)+3) % 4)

class Double:
    @classmethod
    def Parse(cls, data, offset):
        return (struct.unpack_from('d', data, offset)[0], 8)
    @classmethod
    def Dump(cls, value):
        return struct.pack('d', value)

def Tuple(*class_arg):
    class tuple_cl:
        @classmethod
        def Parse(cls, data, offset):
            result = []
            reslen = 0
            for t in class_arg:
                dt, ln = t.Parse(data, offset+reslen)
                result.append(dt)
                reslen += ln
            return (result, reslen)
        @classmethod
        def Dump(cls, *values):
            if len(values) == 1 and isinstance(values[0], tuple):
                return cls.Dump(*values[0])
            result = b''
            for arg, value in zip(class_arg, values):
                result += arg.Dump(value)
            return result
    return tuple_cl

def Vector(tipe):
    class vector_cl:
        @classmethod
        def Parse(cls, data, offset):
            result = []
            reslen = 0
            _, ln = Int().Parse(data, offset) # 0x1cb5c415
            reslen += ln
            count, ln = Int().Parse(data, offset+reslen)
            reslen += ln
            for _ in range(count):
                dt, ln = tipe.Parse(data, offset+reslen)
                result.append(dt)
                reslen += ln
            return (result, reslen)
        @classmethod
        def Dump(cls, value):
            result = b''
            for val in value:
                result += tipe.Dump(val)
    return vector_cl

def decompose(n):
    x = 2
    y = 2
    
    f = lambda x: (x * x + 1) % n
    
    def nod(x, y):
        while True:
            x %= y
            if x == 0:
                return y
            y %= x
            if y == 0:
                return x
    
    i = 0
    while True:
        x = f(x)
        y = f(f(y))
        p = nod(n, abs(x - y))
        if p > 1:
            break
        i += 1
        
    q = n // p
    
    logging.debug("{} = {} * {}".format(n, p, q))
    
    if p < q:
        return (p, q)
    return (q, p)

OK = 0
ERROR = 1 
    
class Session:
    AUTH_KEY_FILE = 'auth.key'
    PUBLIC_KEY_FILE = 'public.pem'
    
    def __init__(self):
        self.datano = 0
        self.map = dict()
        self.data = bytes()
        self.message_id = 0
    
    def run(self):
        self.sock = socket.socket()
        self.sock.connect(("149.154.167.40", 443))
        
        try:
            with open(self.AUTH_KEY_FILE, 'rb') as key_file:
                self.auth_key = key_file.read()
        except:
            self.nonce = random.getrandbits(128)
            self.sendUnencrypted(self.req_pq(self.nonce))
        else:
            pass
            # послать приветствие
        
        while True:
            if not self.receive(4):
                break
            if not self.receive(int.from_bytes(self.data[:4], 'little')):
                break
            if not self.process():
                break
                
    def receive(self, size):
        while True:
            try:
                data = self.sock.recv(size - len(self.data))
            except OSError:
                return False
        if len(data) == 0:
            return False
        self.data = self.data + data
        return True       
    
    def process(self):
        if int.from_bytes(self.data[-4:0], 'little') != int.from_bytes(zlib.crc32(self.data[:-4], 'little')):
            return True
        return self.process_message(self.data[8:-4])
        
    def process_message(self, message):
        auth_key_id = message[0:8]
        message_id = message[8:16]
        message_len = int.from_bytes(message[16:20])
        return self.process_func(message[20:])
        
    def process_func(self, message):
        func = int.from_bytes(message[:4], "little")
        if func == 0x05162463:
            return self.process_resPQ(*Tuple(Int(128), Int(128), String, Vector(Long)).Parse(message, 4)[0])
        elif func == 0x79cb045d:
            return self.process_server_DH_params_fail(*Tuple(Int(128), Int(128), Int(128)).Parse(message, 4)[0])
        elif func == 0xd0e8075c:
            return self.process_server_DH_params_ok(*Tuple(Int(128), Int(128), String).Parse(message, 4)[0])

    def process_resPQ(self, nonce, server_nonce, pq, fingerprints):
        logging.debug("resPQ(nonce={!r}, server_nonce={!r}, pq={!r}, fingerprints={!r}".format(nonce, server_nonce, pq, fingerprints))
        if nonce != self.nonce:
            return False
        self.server_nonce = server_nonce

        pq = int.from_bytes(pq, 'big')
        p, q = decompose(pq)

        # перенести?
        try:
            with open(self.PUBLIC_KEY_FILE, 'rb') as f:
                self.server_public_key = rsa.PublicKey.load_pkcs1(f.read())
            # TODO: проверить отпечаток
            sha = SHA.new()
            sha.update(self.rsa_public_key(self.server_public_key.n.to_bytes(256, 'big'), self.server_public_key.e.to_bytes(4, 'big')))
            sha = sha.digest()
            logging.debug('Server public fingerprint: {!r}'.format(sha))
            for fp_id, fp in enumerate(fingerprints):
                if fp == sha:
                    fingerprint_id = fp_id
                    break
            else:
                logging.error('Server public key doesn\'t correspond to the given fingerprints.')
                return False
        except:
            logging.error('Server public key is missing!')
            return False
        self.new_nonce = random.getrandbits(256)
        data = self.p_q_inner_data(pq.to_bytes(8, 'big'), p.to_bytes(4, 'big'), q.to_bytes(4, 'big'), nonce, server_nonce, self.new_nonce)
        encrypted_data = rsa.encrypt(data, self.server_public_key)
        self.sendUnencrypted(self.req_DH_params(nonce, server_nonce, p.to_bytes(4, 'big'), q.to_bytes(4, 'big'), fingerprints[fingerprint_id], encrypted_data))
        return True
        
    def process_server_DH_params_fail(self, nonce, server_nonce, new_nonce_hash):
        logging.debug("server_DH_params_fail(nonce={!r}, server_nonce={!r}, new_nonce_hash={!r})".format(nonce, server_nonce, new_nonce_hash))
        return False
    
    def process_server_DH_params_ok(self, nonce, server_nonce, encrypted_answer):
        logging.debug("server_DH_params_ok(nonce={!r}, server_nonce={!r}, encrypted_answer={!r})".format(nonce, server_nonce, encrypted_answer))

        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        
        server_nonce_str = server_nonce.to_bytes(16, 'little')
        new_nonce_str = self.new_nonce.to_bytes(16, 'little')
        sn_nn = SHA.new()
        sn_nn.update(server_nonce_str + new_nonce_str)
        nn_sn = SHA.new()
        nn_sn.update(new_nonce_str + server_nonce_str)
        nn_nn = SHA.new()
        nn_nn.update(new_nonce_str + new_nonce_str)
        tmp_aes_key = nn_sn.digest() + sn_nn.digest()[0:12]
        tmp_aes_iv = sn_nn.digest()[12:20] + nn_nn.digest() + new_nonce_str[0:4]
        
        aes_ige = AES_IGE(tmp_aes_key, tmp_aes_iv)
        answer_with_hash = aes_ige.decrypt(encrypted_answer)
        answer, answer_len = Tuple(Int(), Int(128), Int(128), Int(), String, String, Int()).Parse(answer_with_hash[20:])
        
        answer_sha = SHA.new()
        answer_sha.update(answer_with_hash[20:20+answer_len])
        if answer_with_hash[0:20] != answer_sha.digest():
            logging.error('Failed to decrypt answer')
            return False
        
        _, nonce, server_nonce, g, dh_prime, g_a, server_time = answer
        logging.debug("server_DH_inner_data(nonce={!r}, server_nonce={!r}, g={!r}, dh_prime={!r}, g_a={!r}, server_time={!r})".format(nonce, server_nonce, g, dh_prime, g_a, server_time))
    
        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        
        g_a = int.from_bytes(g_a, 'big')
        p = int.from_bytes(dh_prime, 'big')
        
        b = random.getrandbits(2048)
        g_b = pow(g, b, p)
        g_ab = pow(g_a, b, p)
        
        self.auth_key = g_ab.to_bytes(256, 'big')
        
        sha = SHA.new()
        sha.update(self.auth_key)
        self.auth_key_hash = sha.digest()
        return True

    def req_pq(self, nonce):
        logging.debug("req_pq(nonce={!r})".format(nonce))
        return Tuple(Int(), Int(128)).Dump(0x60469778, nonce)
    
    def p_q_inner_data(self, pq, p, q, nonce, server_nonce, new_nonce):
        logging.debug("P_Q_inner_data(pq={!r}, p={!r}, q={!r}, nonce={!r}, server_nonce={!r}, new_nonce={!r})".format(pq, p, q, nonce, server_nonce, new_nonce))
        return Tuple(Int(), String, String, String, Int(128), Int(128), Int(256)).Dump(0x83c95aec, pq, p, q, nonce, server_nonce, new_nonce)
        
    def req_DH_params(self, nonce, server_nonce, p, q, public_key_fingerprint, encrypted_data):
        logging.debug("req_DH_params(nonce={!r}, server_nonce={!r}, p={!r}, q={!r}, public_key_fingerprint={!r}, encrypted_data={!r})".format(nonce, server_nonce, p, q, public_key_fingerprint, encrypted_data))
        return Tuple(Int(), Int(128), Int(128), String, String, Long, String).Dump(0xd712e4be, nonce, server_nonce, p, q, public_key_fingerprint, encrypted_data)

    def rsa_public_key(self, n, e):
        logging.debug("rsa_public_key(n={!r}, e={!r})".format(n, e))
        return Tuple(Int(), String, String).Dump(0x7a19cb76, n, e)
    
    def set_client_DH_params(self, nonce, server_nonce, encrypted_data):
        return Tuple(Int(), Int(128), Int(128), String).Dump(0xf5045f1f, 

    def send(self, data):
        length = len(data) + 12
        data = length.to_bytes(4, "little") + self.datano.to_bytes(4, "little") + data
        data = data + zlib.crc32(data).to_bytes(4, "little")
        self.datano += 1
        self.sock.send(data)
        
    def getMessageId(self):
        msg_id = int(time.time() * (1 << 30)) * 4
        if self.message_id >= msg_id:
            self.message_id += 4
        else:
            self.message_id = msg_id
        return self.message_id
        
    def sendUnencrypted(self, data):
        self.send(int(0).to_bytes(8, "little") + self.getMessageId().to_bytes(8, "little") + len(data).to_bytes(4, "little") + data) 
        
    def sendEncrypted(self, data):
        pass

def main():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    handler = logging.handlers.RotatingFileHandler('test.log', maxBytes=16000000, backupCount=2)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)

    session = Session();
#     session.run()

#     nonce = int("3E0549828CCA27E966B301A48FECE2FC", 16)
#     nonce = nonce.to_bytes(16, 'big')
#     nonce = int.from_bytes(nonce, 'little')
#     req_pq = session.req_pq(nonce)
#     logging.debug("req_pq: ({}) {}".format(len(req_pq), hex(int.from_bytes(req_pq, 'big'))[2:].upper()));
    
    message = int("632416053E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA5739073300817ED48941A08F98100000015C4B51C01000000216BE86C022BB4C3", 16)
    message = message.to_bytes(64, 'big')
    data = session.process_func(message)
    logging.debug("req_DH_params: ({}) {}".format(len(data), hex(int.from_bytes(data, 'big'))[2:].upper()));

if __name__ == "__main__":
    main()

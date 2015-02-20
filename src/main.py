# -*- coding: utf8 -*-
import logging
import logging.handlers
import traceback
import rsa
from Crypto.Random import random
from crypto import *
from format import *
from session import CryptoSession
from maths import *
import yaml
from optparse import OptionParser

AUTH_KEY_FILE = 'auth.key'
PUBLIC_KEY_FILE = 'public.pem'

class DataSession(CryptoSession):

    def __init__(self):
        CryptoSession.__init__(self)
        
#     def Dispatch(self, data):
#         message, _ = Unknown.Parse(data)
#         getattr(self, StructById[message[0]].Name())(*message[1:])
    
#     def Run(self, config):
#         self.Connect(config['server']['address']['host'], config['server']['address']['port'])
#         
#         try:
#             with open(config['client']['auth_key'], 'rb') as auth_key_file:
#                 self.auth_key = auth_key_file.read()
#         except:
#             self.nonce = random.getrandbits(128)
#             self.sendUnencrypted(Unknown.Dump(req_pq.Create(self.nonce)))
#         else:
#             pass

    def Receive(self, timeout):
        data = super().Receive(timeout)
        if data is None:
            return None
        return Unknown.Parse(data)[0]

    def Send(self, data, encrypted=True):
        return super().Send(Unknown.Dump(data), encrypted)
            
    
class Session:
    
    def __init__(self):
        self.datano = 0
        self.map = dict()
        self.data = bytes()
        self.message_id = 0
        self.retry_id = 0
    
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
        elif func == 0x3bcbf734:
            return self.process_dh_gen_ok(*Tuple(Int(128), Int(128), Int(128)).Parse(message, 4)[0]);
        elif func == 0x46dc1fb9:
            return self.process_dh_gen_retry(*Tuple(Int(128), Int(128), Int(128)).Parse(message, 4)[0]);
        elif func == 0xa69dae02:
            return self.process_dh_gen_fail(*Tuple(Int(128), Int(128), Int(128)).Parse(message, 4)[0]);

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
            sha = SHA1(self.rsa_public_key(self.server_public_key.n.to_bytes(256, 'big'), self.server_public_key.e.to_bytes(4, 'big')))
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
        sn_nn = SHA1(server_nonce_str + new_nonce_str)
        nn_sn = SHA1(new_nonce_str + server_nonce_str)
        nn_nn = SHA1(new_nonce_str + new_nonce_str)
        tmp_aes_key = nn_sn + sn_nn[0:12]
        tmp_aes_iv = sn_nn[12:20] + nn_nn + new_nonce_str[0:4]
        
        aes_ige = AES_IGE(tmp_aes_key, tmp_aes_iv)
        answer_with_hash = aes_ige.decrypt(encrypted_answer)
        answer, answer_len = Tuple(Int(), Int(128), Int(128), Int(), String, String, Int()).Parse(answer_with_hash[20:])
        
        answer_sha = SHA1(answer_with_hash[20:20+answer_len])
        if answer_with_hash[0:20] != answer_sha:
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
        
        self.auth_key_hash = SHA1(self.auth_key)[0:8]
        
        data = self.client_DH_inner_data(nonce, server_nonce, self.retry_id, g_b.to_bytes(256, 'big'))
        self.retry_id += 1
        data_with_hash = SHA1(data) + data
        rand_len = (15-(len(data_with_hash)-1)%16)
        data_with_hash = data_with_hash + random.getrandbits(rand_len*8).to_bytes(rand_len, 'big') 
        
        encrypted_data = aes_ige.encrypt(data_with_hash)
        self.sendUnencrypted(self.set_client_DH_params(nonce, server_nonce, encrypted_data))
        return True
    
    def process_dh_gen_ok(self, nonce, server_nonce, new_nonce_hash1):
        logging.debug("process_dh_gen_ok(nonce={!r}, server_nonce={!r}, new_nonce_hash1={!r})".format(nonce, server_nonce, new_nonce_hash1))
        
        return True
    
    def process_dh_gen_retry(self, nonce, server_nonce, new_nonce_hash2):
        logging.debug("process_dh_gen_retry(nonce={!r}, server_nonce={!r}, new_nonce_hash2={!r})".format(nonce, server_nonce, new_nonce_hash2))
        return False
    
    def process_dh_gen_fail(self, nonce, server_nonce, new_nonce_hash3):
        logging.debug("process_dh_gen_fail(nonce={!r}, server_nonce={!r}, new_nonce_hash3={!r})".format(nonce, server_nonce, new_nonce_hash3))
        return False

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
        logging.debug("set_client_DH_params(nonce={!r}, server_nonce={!r}, encrypted_data={!r})".format(nonce, server_nonce, encrypted_data))
        return Tuple(Int(), Int(128), Int(128), String).Dump(0xf5045f1f, nonce, server_nonce, encrypted_data)
    
    def client_DH_inner_data(self, nonce, server_nonce, retry_id, g_b):
        logging.debug("client_DH_inner_data(nonce={!r}, server_nonce={!r}, retry_id={!r}, g_b={!r})".format(nonce, server_nonce, retry_id, g_b))
        return Tuple(Int(), Int(128), Int(128), Long, String).Dump(0x6643b654, nonce, server_nonce, retry_id, g_b)

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
    parser = OptionParser()
    parser.add_option("-c", "--config", help="yaml config file name", default="config.yaml")
    (options, args) = parser.parse_args()

    config = yaml.load(options.config)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    handler = logging.handlers.RotatingFileHandler(config["log_file"], maxBytes=16000000, backupCount=2)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    session = DataSession();
    session.Run(config)

#     try:
#         with open(AUTH_KEY_FILE, 'rb') as key_file:
#             self.auth_key = key_file.read()
#     except:
#         self.nonce = random.getrandbits(128)
#         self.sendUnencrypted(self.req_pq(self.nonce))
#     else:
#         pass
#         # послать приветствие
    
    while True:
        try:
            data = session.Receive(0) # тут ващет не ноль
            if data is None:
                continue
            session.Dispatch(data)
        except:
            logging.error(traceback.format_exc())
            break

#     nonce = int("3E0549828CCA27E966B301A48FECE2FC", 16)
#     nonce = nonce.to_bytes(16, 'big')
#     nonce = int.from_bytes(nonce, 'little')
#     req_pq = session.req_pq(nonce)
#     logging.debug("req_pq: ({}) {}".format(len(req_pq), hex(int.from_bytes(req_pq, 'big'))[2:].upper()));
    
#     message = int("632416053E0549828CCA27E966B301A48FECE2FCA5CF4D33F4A11EA877BA4AA5739073300817ED48941A08F98100000015C4B51C01000000216BE86C022BB4C3", 16)
#     message = message.to_bytes(64, 'big')
#     data = session.process_func(message)
#     logging.debug("req_DH_params: ({}) {}".format(len(data), hex(int.from_bytes(data, 'big'))[2:].upper()));

if __name__ == "__main__":
    main()

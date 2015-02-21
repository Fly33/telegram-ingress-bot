# -*- coding: utf8 -*-
import logging
import logging.handlers
import traceback
import rsa
from Crypto.Cipher import XOR
from Crypto.Random import random
from crypto import *
from format import *
from session import CryptoSession, ConnectionError
from maths import *
import yaml
from optparse import OptionParser

AUTH_KEY_FILE = 'auth.key'
PUBLIC_KEY_FILE = 'public.pem'

class DataSession(CryptoSession):

    def __init__(self):
        CryptoSession.__init__(self)

    def Receive(self, timeout):
        data = super().Receive(timeout)
        if data is None:
            return None
        return Unknown.Parse(data)[0]

    def Send(self, data, encrypted=True):
        return super().Send(Unknown.Dump(data), encrypted)


class Bot:
    def __init__(self, config):
        self.config = config
        self.retry_id = 0
        
    def Run(self):
        self.session = DataSession();
        self.session.Connect(config['address']['host'], config['address']['port'])
    
        try:
            with open(config['auth_key'], 'rb') as auth_key_file:
                auth_key = auth_key_file.read()
        except:
            self.nonce = random.getrandbits(128)
            self.session.send(req_pq.Create(self.nonce), False)
        else:
            pass
        
        while True:
            try:
                data = self.session.Receive(0) # тут ващет не ноль
                if data is None:
                    continue
                self.Dispatch(data)
            except ConnectionError:
                # TODO: reconnect
                break
            except:
                logging.error(traceback.format_exc())
                break
    
    def Dispatch(self, data):
        return getattr(self, 'process_' + StructById[message[0]].Name())(*message[1:])
     
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
                server_public_key = rsa.PublicKey.load_pkcs1(f.read())
            # проверить отпечаток
            sha = SHA1(Unknown.Dump(rsa_public_key.Create(server_public_key.n, server_public_key.e)))
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
        data = Unknown.Dump(p_q_inner_data.Create(pq, p, q, nonce, server_nonce, self.new_nonce))
        encrypted_data = rsa.encrypt(data, server_public_key)
        self.session.send(req_DH_params.Create(nonce, server_nonce, p, q, fingerprints[fingerprint_id], encrypted_data))
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
        
        server_nonce_str = Int(16).Dump(server_nonce)
        new_nonce_str = Int(16).Dump(self.new_nonce)
        sn_nn = SHA1(server_nonce_str + new_nonce_str)
        nn_sn = SHA1(new_nonce_str + server_nonce_str)
        nn_nn = SHA1(new_nonce_str + new_nonce_str)
        tmp_aes_key = nn_sn + sn_nn[0:12]
        tmp_aes_iv = sn_nn[12:20] + nn_nn + new_nonce_str[0:4]
        
        aes_ige = AES_IGE(tmp_aes_key, tmp_aes_iv)
        answer_with_hash = aes_ige.decrypt(encrypted_answer)
        answer, answer_len = server_DH_inner_data.Parse(answer_with_hash[20:])
        
        answer_sha = SHA1(answer_with_hash[20:20+answer_len])
        if answer_with_hash[0:20] != answer_sha:
            logging.error('Failed to decrypt answer')
            return False
        
        _, nonce, server_nonce, g, p, g_a, server_time = answer
        logging.debug("server_DH_inner_data(nonce={!r}, server_nonce={!r}, g={!r}, dh_prime={!r}, g_a={!r}, server_time={!r})".format(nonce, server_nonce, g, p, g_a, server_time))
    
        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        
        b = random.getrandbits(2048)
        g_b = pow(g, b, p)
        g_ab = pow(g_a, b, p)
        
        self.auth_key = g_ab.to_bytes(256, 'big')
        
        self.auth_key_hash = SHA1(self.auth_key)[0:8]
        
        data = Unknown.Dump(client_DH_inner_data.Create(nonce, server_nonce, self.retry_id, g_b))
        self.retry_id += 1
        data_with_hash = SHA1(data) + data
        rand_len = (15-(len(data_with_hash)-1)%16)
        data_with_hash = data_with_hash + random.getrandbits(rand_len*8).to_bytes(rand_len, 'big') 
        
        encrypted_data = aes_ige.encrypt(data_with_hash)
        self.sendUnencrypted(self.set_client_DH_params(nonce, server_nonce, encrypted_data))
        return True
    
    def process_dh_gen_ok(self, nonce, server_nonce, new_nonce_hash1):
        logging.debug("process_dh_gen_ok(nonce={!r}, server_nonce={!r}, new_nonce_hash1={!r})".format(nonce, server_nonce, new_nonce_hash1))
        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        # TODO: проверить хэш
        self.salt = XOR.new(self.new_nonce[0:8]).encrypt(self.server_nonce[0:8])
        return True
    
    def process_dh_gen_retry(self, nonce, server_nonce, new_nonce_hash2):
        logging.debug("process_dh_gen_retry(nonce={!r}, server_nonce={!r}, new_nonce_hash2={!r})".format(nonce, server_nonce, new_nonce_hash2))
        # TODO: попробовать снова
        return False
    
    def process_dh_gen_fail(self, nonce, server_nonce, new_nonce_hash3):
        logging.debug("process_dh_gen_fail(nonce={!r}, server_nonce={!r}, new_nonce_hash3={!r})".format(nonce, server_nonce, new_nonce_hash3))
        # TODO: попробовать снова
        return False

def main():
    parser = OptionParser()
    parser.add_option("-c", "--config", help="yaml config file name", default="config.yaml")
    (options, args) = parser.parse_args()

    config = yaml.load(options.config)

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    handler = logging.handlers.RotatingFileHandler(config["log"], maxBytes=16000000, backupCount=2)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    bot = Bot(config['telegram'])
    bot.Run()

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

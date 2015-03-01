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


class DecryptError(RuntimeError):
    pass


def AES_IGE_TLG(AES_IGE):
    def encrypt(self, data):
        data = Unknown.Dump(data)
        data_with_hash = SHA1(data) + data
        rand_len = (15-(len(data_with_hash)-1)%16)
        data_with_hash = data_with_hash + random.getrandbits(rand_len*8).to_bytes(rand_len, 'big')
        return super().encrypt(data_with_hash)         

    def decrypt(self, data):
        data_with_hash = super().decrypt(data)
        data, data_len = Unknown.Parse(data_with_hash[20:])
        if data_with_hash[0:20] != SHA1(data_with_hash[20:20+data_len]):
            raise DecryptError("Failed to decrypt message")
        return data

class Telegram:
    def __init__(self, config):
        self.config = config
        
    def Run(self):
        self.session = DataSession();
        self.session.Connect(config['address']['host'], config['address']['port'])
    
        try:
            with open(self.config['auth_key'], 'rb') as auth_key_file:
                auth_key = auth_key_file.read()
            logging.info("Auth key is loaded.")
        except:
            logging.info("Generating new auth key.")
            self.retry_id = 0
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
        if data not in StructById:
            logging.debug('Unknown response: {}'.format(hex(data[0])))
            return
        return getattr(self, 'process_' + StructById[data[0]].Name())(*data[1:])
        
     
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
                if fp == sha[-8:0]:
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
        
        self.aes_ige = AES_IGE_TLG(tmp_aes_key, tmp_aes_iv)
        answer = aes_ige.decrypt(encrypted_answer)
        
        return self.Dispatch(answer)
    
    def process_server_DH_inner_data(self, nonce, server_nonce, g, p, g_a, server_time):
        logging.debug("server_DH_inner_data(nonce={!r}, server_nonce={!r}, g={!r}, dh_prime={!r}, g_a={!r}, server_time={!r})".format(nonce, server_nonce, g, p, g_a, server_time))
    
        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        
        b = random.getrandbits(2048)
        g_b = pow(g, b, p)
        g_ab = pow(g_a, b, p)
        
        self.auth_key = g_ab.to_bytes(256, 'big')
        self.auth_key_hash = SHA1(self.auth_key)[-8:0]
        
        encrypted_data = aes_ige.encrypt(client_DH_inner_data.Create(nonce, server_nonce, self.retry_id, g_b))
        self.retry_id += 1
        self.send(set_client_DH_params.Create(nonce, server_nonce, encrypted_data), False)
        return True
    
    def process_dh_gen_ok(self, nonce, server_nonce, new_nonce_hash1):
        logging.debug("process_dh_gen_ok(nonce={!r}, server_nonce={!r}, new_nonce_hash1={!r})".format(nonce, server_nonce, new_nonce_hash1))
        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        # TODO: проверить хэш
        with open(self.config['auth_key'], 'wb') as auth_key_file:
            auth_key_file.write(auth_key)
        self.salt = XOR.new(self.new_nonce[0:8]).encrypt(self.server_nonce[0:8])
        del self.nonce
        del self.server_nonce
        del self.new_nonce
        del self.retry_id
        del self.aes_ige
        # TODO: создать сессию
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

    telegram = Telegram(config['telegram'])
    telegram.Run()

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

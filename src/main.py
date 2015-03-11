# -*- coding: utf8 -*-
import logging
import logging.handlers
import traceback
import yaml
from optparse import OptionParser

import rsa
from Crypto.Cipher import XOR
from Crypto.Random import random

from crypto import *
from format import *
from session import CryptoSession, ConnectionError
from algorithm import *
from error import *
from timer import *

class DataSession(CryptoSession):
    def __init__(self):
        super().__init__()

    def Receive(self, timeout):
        data = super().Receive(timeout)
        if data is None:
            return None
        return Box.Parse(data)[0]

    def Send(self, data, encrypted=True):
        return super().Send(Box.Dump(data), encrypted)


class AES_IGE_TLG(AES_IGE):
    def encrypt(self, data):
        data = Box.Dump(data)
        data_with_hash = SHA1(data) + data
        rand_len = (15-(len(data_with_hash)-1)%16)
        data_with_hash = data_with_hash + random.getrandbits(rand_len*8).to_bytes(rand_len, 'big')
        return super().encrypt(data_with_hash)         

    def decrypt(self, data):
        data_with_hash = super().decrypt(data)
        data, data_len = Box.Parse(data_with_hash[20:])
        if data_with_hash[0:20] != SHA1(data_with_hash[20:20+data_len]):
            raise DecryptError("Failed to decrypt message")
        return data
    
def Hex(data):
    if isinstance(data, int):
        return hex(data)[2:]
    elif isinstance(data, tuple) or isinstance(data, list):
        return str(tuple(Hex(x) for x in data))
    elif isinstance(data, bytes):
        return hex(int.from_bytes(data, 'big'))[2:]
    else:
        return data

class Telegram:
    def __init__(self, config):
        self.config = config
        self.timer = Timer()
        
    def Run(self):
        self.session = DataSession();
        self.session.Connect(self.config['address']['host'], self.config['address']['port'])
    
        try:
            with open(self.config['auth_key'], 'rb') as auth_key_file:
                self.session.auth_key = auth_key_file.read()
            logging.info("Auth key is loaded.")
        except:
            logging.info("Generating new auth key.")
            self.retry_id = 0
            self.nonce = random.getrandbits(128)
            self.session.Send(req_pq.Create(self.nonce), False)
        else:
            pass
        
        while True:
            try:
                data = self.session.Receive(self.timer.GetTimeout())
                if data is None:
                    continue
                self.Dispatch(data)
            except ConnectionError:
                # TODO: reconnect
                break
            except:
                logging.error(traceback.format_exc())
                break # TODO: может что-нить поумнее сделать?
    
    def Dispatch(self, data):
        if data[0] not in StructById:
            logging.debug('Unknown response: {}'.format(hex(data[0])))
            return
        return getattr(self, 'process_' + StructById[data[0]].Name())(*data[1:])
        
     
    def process_resPQ(self, nonce, server_nonce, pq, fingerprints):
        logging.debug("resPQ(nonce={}, server_nonce={}, pq={}, fingerprints={}".format(Hex(nonce), Hex(server_nonce), Hex(pq), Hex(fingerprints)))
        if nonce != self.nonce:
            return False
        self.server_nonce = server_nonce

        p, q = Decompose(pq)

        # перенести?
        try:
            with open(self.config["public_key"], 'rb') as f:
                server_public_key = rsa.PublicKey.load_pkcs1(f.read())
            # проверить отпечаток
            sha = SHA1(rsa_public_key.Dump(server_public_key.n, server_public_key.e))
            logging.debug('Server public fingerprint: {}'.format(Hex(sha)))
            for fp_id, fp in enumerate(fingerprints):
                if fp == int.from_bytes(sha[-8:], 'little'):
                    fingerprint_id = fp_id
                    break
            else:
                logging.error('Server public key doesn\'t correspond to the given fingerprints.')
                return False
        except:
            logging.error('Server public key is missing!')
            return False
        self.new_nonce = random.getrandbits(256)
        data = Box.Dump(p_q_inner_data.Create(pq, p, q, nonce, server_nonce, self.new_nonce))
        data = SHA1(data) + data
        data = data + random.getrandbits((255 - len(data))*8).to_bytes(255 - len(data), 'big')
        encrypted_data = pow(int.from_bytes(data, 'big'), server_public_key.e, server_public_key.n).to_bytes(256, 'big')
#         encrypted_data = rsa.encrypt(data, server_public_key)
        self.session.Send(req_DH_params.Create(nonce, server_nonce, p, q, fingerprints[fingerprint_id], encrypted_data), False)
        return True
        
    def process_server_DH_params_fail(self, nonce, server_nonce, new_nonce_hash):
        logging.debug("server_DH_params_fail(nonce={}, server_nonce={}, new_nonce_hash={})".format(Hex(nonce), Hex(server_nonce), Hex(new_nonce_hash)))
        return False
    
    def process_server_DH_params_ok(self, nonce, server_nonce, encrypted_answer):
        logging.debug("server_DH_params_ok(nonce={}, server_nonce={}, encrypted_answer={})".format(Hex(nonce), Hex(server_nonce), Hex(encrypted_answer)))

        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        
        server_nonce_str = Int(128).Dump(server_nonce)
        new_nonce_str = Int(256).Dump(self.new_nonce)
        sn_nn = SHA1(server_nonce_str + new_nonce_str)
        nn_sn = SHA1(new_nonce_str + server_nonce_str)
        nn_nn = SHA1(new_nonce_str + new_nonce_str)
        tmp_aes_key = nn_sn + sn_nn[0:12]
        tmp_aes_iv = sn_nn[12:20] + nn_nn + new_nonce_str[0:4]
        
        self.aes_ige = AES_IGE_TLG(tmp_aes_key, tmp_aes_iv)
        answer = self.aes_ige.decrypt(encrypted_answer)
        
        return self.Dispatch(answer)
    
    def process_server_DH_inner_data(self, nonce, server_nonce, g, p, g_a, server_time):
        logging.debug("server_DH_inner_data(nonce={}, server_nonce={}, g={}, dh_prime={}, g_a={}, server_time={})".format(Hex(nonce), Hex(server_nonce), Hex(g), Hex(p), Hex(g_a), Hex(server_time)))
    
        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        
        self.session.time_offset = server_time - time()
        
        b = random.getrandbits(2048)
        g_b = pow(g, b, p)
        g_ab = pow(g_a, b, p)
        
        self.session.auth_key = g_ab.to_bytes(256, 'big')
        
        encrypted_data = self.aes_ige.encrypt(client_DH_inner_data.Create(nonce, server_nonce, self.retry_id, g_b))
        self.retry_id += 1
        self.session.Send(set_client_DH_params.Create(nonce, server_nonce, encrypted_data), False)
        return True
    
    def process_dh_gen_ok(self, nonce, server_nonce, new_nonce_hash1):
        logging.debug("process_dh_gen_ok(nonce={}, server_nonce={}, new_nonce_hash1={})".format(Hex(nonce), Hex(server_nonce), Hex(new_nonce_hash1)))
        if nonce != self.nonce:
            return False
        if server_nonce != self.server_nonce:
            return False
        # TODO: проверить хэш
        with open(self.config['auth_key'], 'wb') as auth_key_file:
            auth_key_file.write(self.session.auth_key)
        self.session.salt = XOR.new(self.new_nonce[0:8]).encrypt(self.server_nonce[0:8])
        del self.nonce
        del self.server_nonce
        del self.new_nonce
        del self.retry_id
        del self.aes_ige

        self.timer.Add(time(), lambda: self.session.Send(ping.Create(random.getrandbits(64))))
        return True
    
    def process_dh_gen_retry(self, nonce, server_nonce, new_nonce_hash2):
        logging.debug("process_dh_gen_retry(nonce={}, server_nonce={}, new_nonce_hash2={})".format(Hex(nonce), Hex(server_nonce), Hex(new_nonce_hash2)))
        # TODO: попробовать снова
        return False
    
    def process_dh_gen_fail(self, nonce, server_nonce, new_nonce_hash3):
        logging.debug("process_dh_gen_fail(nonce={}, server_nonce={}, new_nonce_hash3={})".format(Hex(nonce), Hex(server_nonce), Hex(new_nonce_hash3)))
        # TODO: попробовать снова
        return False
    
    def process_ping(self, ping_id):
        logging.debug("process_ping(ping_id={})".format(ping_id))
        self.session.Send(pong.Create(0, ping_id)) # ноль???
        return True
    
    def process_pong(self, msg_id, ping_id):
        logging.debug("process_pong(msg_id={}, ping_id={})".format(msg_id, ping_id))
        return True

def main():
    parser = OptionParser()
    parser.add_option("-c", "--config", help="yaml config file name", default="config.yaml")
    (options, args) = parser.parse_args()

    try:
        with open(options.config, 'r') as config_file:
            config = yaml.load(config_file.read())
    except:
        logging.error('Unable to open "{}" file.'.format(options.config))
        return

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

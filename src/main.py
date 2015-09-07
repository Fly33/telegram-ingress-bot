# -*- coding: utf8 -*-
import logging
import logging.handlers
import traceback
import yaml
from optparse import OptionParser
from time import time as Now

import rsa
from Crypto.Cipher import XOR
from Crypto.Random import random

from crypto import *
from format import *
from session import CryptoSession, ConnectionError
from algorithm import *
from error import *
from timer import *
from pip._vendor.requests.sessions import session

class DataSession(CryptoSession):
    def __init__(self):
        super().__init__()

    def Receive(self, timeout):
        message = super().Receive(timeout)
        if message is None:
            return None
        id, seq, data = message
        logging.debug("Recv data: {}".format(self.Hex(data)))
        return (id, seq, Box.Parse(data)[0])

    def Send(self, message_id, seq_no, data, encrypted=True):
        data = Box.Dump(data)
        logging.debug("Send data: {}".format(self.Hex(data)))
        return super().Send(message_id, seq_no, data, encrypted)

    @staticmethod
    def Hex(data):
        return ''.join(('\n\t{:03x}0 |'.format(i) + ''.join((' {:02x}'.format(int.from_bytes(data[i*16+j:i*16+j+1], 'big')) for j in range(16) if i*16+j < len(data))) for i in range((len(data)-1)//16+1)))

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
        self.ping_timer_id = self.timer.New()
        self.message_id = 0
        self.n_relevant = 0
        self.time_offset = 0
        self.queue = []
        self.acks = []
        
    def Run(self):
        self.session = DataSession();
        self.session.Connect(self.config['address']['host'], self.config['address']['port'])
    
        try:
            raise # TODO: убрать
            with open(self.config['auth_key'], 'rb') as auth_key_file:
                self.session.auth_key = auth_key_file.read()
            logging.info("Auth key is loaded.")
        except:
            logging.info("Generating new auth key.")
            self.retry_id = 0
            self.nonce = random.getrandbits(128)
            self.Send(req_pq.Create(self.nonce), False, False)
        else:
            pass
        
        while True:
            try:
                message = self.session.Receive(self.timer.GetTimeout())
                if message is not None:
                    self.Dispatch(*message)
                self.timer.Process()
                self.Flush()
            except ConnectionError:
                # TODO: reconnect
                break
            except:
                logging.error(traceback.format_exc())
                break # TODO: может что-нить поумнее сделать?
    
    def getMessageId(self):
        msg_id = int((Now() + self.time_offset)  * (1 << 30)) * 4
        if self.message_id >= msg_id:
            self.message_id += 4
        else:
            self.message_id = msg_id
        return self.message_id
    
    def getSeqNo(self, relevant=True):
        seq_no = self.n_relevant * 2
        if relevant:
            seq_no += 1
            self.n_relevant += 1
        return seq_no
        
    def _Send(self, msg_id, seq_no, data, encrypted=True):
        logging.debug('Sending message: msgid={}, seqno={}, data={}'.format(msg_id, seq_no, Box[data[0]].Name() if data[0] in Box else "<unknown>"))
        self.timer.Set(self.ping_timer_id, Now() + 1, self.Send, ping.Create(random.getrandbits(64)), relevant=False)
        return self.session.Send(msg_id, seq_no, data, encrypted)
        
    def Send(self, data, relevant=True, encrypted=True):
        msg_id = self.getMessageId()
        seq_no = self.getSeqNo(relevant)
        logging.debug('Queueing message: msgid={}, seqno={}, data={}'.format(msg_id, seq_no, Box[data[0]].Name() if data[0] in Box else "<unknown>"))
        # TODO: сделать перезапрос акков?
        if encrypted:
            self.queue.append((msg_id, seq_no, data))
            return True
        return self._Send(msg_id, seq_no, data, encrypted)
    
    def Flush(self):
        if self.acks:
            self.Send(msgs_ack.Create(self.acks), relevant=False)
            self.acks = []
        if not self.queue:
            return True
        if len(self.queue) == 1:
            msg_id, seq_no, data = self.queue[0]
        else:
            msg_id, seq_no, data = self.getMessageId(), self.getSeqNo(False), msg_container.Create(self.queue)
        self.queue = []
        return self._Send(msg_id, seq_no, data)
    
    def Dispatch(self, message_id, seq_no, data):
        logging.debug("Received message: msgid={}, seqno={}, data={}".format(message_id, seq_no, Box[data[0]].Name() if data[0] in Box else "<unknown>"))
        message_handler = MessageHandler(self, message_id, seq_no)
        return message_handler.Dispatch(data)


class MessageHandler:
    def __init__(self, application, message_id, seqno):
        self.application = application
        self.message_id = message_id
        self.seqno = seqno
    
    def Dispatch(self, data):
        if data[0] not in Box:
            logging.debug('Unknown response: {}'.format(hex(data[0])))
            return
        return getattr(self, 'process_' + Box[data[0]].Name())(*data[1:])
    
    def Send(self, data, relevant=True, encrypted=True):
        return self.application.Send(data, relevant, encrypted)
        
    def Ack(self):
        self.application.acks.append(self.message_id)
        return True
        
    def process_resPQ(self, nonce, server_nonce, pq, fingerprints):
        logging.debug("resPQ(nonce={}, server_nonce={}, pq={}, fingerprints={}".format(Hex(nonce), Hex(server_nonce), Hex(pq), Hex(fingerprints)))
        if nonce != self.application.nonce:
            return False
        self.application.server_nonce = server_nonce

        p, q = Decompose(pq)

        # перенести?
        try:
            with open(self.application.config["public_key"], 'rb') as f:
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
        self.application.new_nonce = random.getrandbits(256)
        data = Box.Dump(p_q_inner_data.Create(pq, p, q, nonce, server_nonce, self.application.new_nonce))
        data = SHA1(data) + data
        data = data + random.getrandbits((255 - len(data))*8).to_bytes(255 - len(data), 'big')
        encrypted_data = pow(int.from_bytes(data, 'big'), server_public_key.e, server_public_key.n).to_bytes(256, 'big')
#         encrypted_data = rsa.encrypt(data, server_public_key)
        self.Send(req_DH_params.Create(nonce, server_nonce, p, q, fingerprints[fingerprint_id], encrypted_data), False, False)
        return True
        
    def process_server_DH_params_fail(self, nonce, server_nonce, new_nonce_hash):
        logging.debug("server_DH_params_fail(nonce={}, server_nonce={}, new_nonce_hash={})".format(Hex(nonce), Hex(server_nonce), Hex(new_nonce_hash)))
        return False
    
    def process_server_DH_params_ok(self, nonce, server_nonce, encrypted_answer):
        logging.debug("server_DH_params_ok(nonce={}, server_nonce={}, encrypted_answer={})".format(Hex(nonce), Hex(server_nonce), Hex(encrypted_answer)))

        if nonce != self.application.nonce:
            return False
        if server_nonce != self.application.server_nonce:
            return False
        
        server_nonce_str = Int128.Dump(server_nonce)
        new_nonce_str = Int256.Dump(self.application.new_nonce)
        sn_nn = SHA1(server_nonce_str + new_nonce_str)
        nn_sn = SHA1(new_nonce_str + server_nonce_str)
        nn_nn = SHA1(new_nonce_str + new_nonce_str)
        tmp_aes_key = nn_sn + sn_nn[0:12]
        tmp_aes_iv = sn_nn[12:20] + nn_nn + new_nonce_str[0:4]
        
        self.application.aes_ige = AES_IGE_TLG(tmp_aes_key, tmp_aes_iv)
        answer = self.application.aes_ige.decrypt(encrypted_answer)
        
        return self.Dispatch(answer)
    
    def process_server_DH_inner_data(self, nonce, server_nonce, g, p, g_a, server_time):
        logging.debug("server_DH_inner_data(nonce={}, server_nonce={}, g={}, dh_prime={}, g_a={}, server_time={})".format(Hex(nonce), Hex(server_nonce), Hex(g), Hex(p), Hex(g_a), Hex(server_time)))
    
        if nonce != self.application.nonce:
            return False
        if server_nonce != self.application.server_nonce:
            return False
        
        self.application.time_offset = server_time - Now()
        
        b = random.getrandbits(2048)
        g_b = pow(g, b, p)
        g_ab = pow(g_a, b, p)
        
        self.application.session.auth_key = g_ab.to_bytes(256, 'big')
        
        encrypted_data = self.application.aes_ige.encrypt(client_DH_inner_data.Create(nonce, server_nonce, self.application.retry_id, g_b))
        self.application.retry_id += 1
        self.Send(set_client_DH_params.Create(nonce, server_nonce, encrypted_data), False, False)
        return True
    
    def process_dh_gen_ok(self, nonce, server_nonce, new_nonce_hash1):
        logging.debug("process_dh_gen_ok(nonce={}, server_nonce={}, new_nonce_hash1={})".format(Hex(nonce), Hex(server_nonce), Hex(new_nonce_hash1)))
        if nonce != self.application.nonce:
            return False
        if server_nonce != self.application.server_nonce:
            return False
        # TODO: проверить хэш
        with open(self.application.config['auth_key'], 'wb') as auth_key_file:
            auth_key_file.write(self.application.session.auth_key)
        self.application.session.salt = XOR.new(self.application.new_nonce.to_bytes(32, 'little')[0:8]).encrypt(self.application.server_nonce.to_bytes(16, 'little')[0:8])
        del self.application.nonce
        del self.application.server_nonce
        del self.application.new_nonce
        del self.application.retry_id
        del self.application.aes_ige

        # TODO: получить код
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
        self.Send(pong.Create(self.message_id, ping_id), relevant=False)
        return True
    
    def process_pong(self, msg_id, ping_id):
        logging.debug("process_pong(msg_id={}, ping_id={})".format(msg_id, ping_id))
        return True
    
    def process_msg_container(self, messages):
        logging.debug("process_msg_container(messages={}):".format(messages))
        for message_id, seqno, data in messages:
            if not self.application.Dispatch(message_id, seqno, data):
                return False
        return True

    def process_new_session_created(self, first_msg_id, unique_id, server_salt):
        logging.debug("process_new_session_created(first_msg_id={}, unique_id={}, server_salt={})".format(first_msg_id, unique_id, server_salt))
        self.application.session.salt = Long.Dump(server_salt)
        self.application.session.message_id = first_msg_id
        self.Ack()
        return True
    
    def process_bad_msg_notification(self, bad_msg_id, bad_msg_seqno, error_code):
        logging.debug("process_bad_msg_notification(bad_msg_id={}, bad_msg_seqno={}, error_code={})".format(bad_msg_id, bad_msg_seqno, error_code))
        if error_code == 16:
            logging.error("Bad message (msgid={}, seqno={}, error={}): msg_id too low (most likely, client time is wrong; it would be worthwhile to synchronize it using msg_id notifications and re-send the original message with the “correct” msg_id or wrap it in a container with a new msg_id if the original message had waited too long on the client to be transmitted)".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 17:
            logging.error("Bad message (msgid={}, seqno={}, error={}): msg_id too high (similar to the previous case, the client time has to be synchronized, and the message re-sent with the correct msg_id)".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 18:
            logging.error("Bad message (msgid={}, seqno={}, error={}): incorrect two lower order msg_id bits (the server expects client message msg_id to be divisible by 4)".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 19:
            logging.error("Bad message (msgid={}, seqno={}, error={}): container msg_id is the same as msg_id of a previously received message (this must never happen)".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 20:
            logging.error("Bad message (msgid={}, seqno={}, error={}): message too old, and it cannot be verified whether the server has received a message with this msg_id or not".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 32:
            logging.error("Bad message (msgid={}, seqno={}, error={}): msg_seqno too low (the server has already received a message with a lower msg_id but with either a higher or an equal and odd seqno)".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 33:
            logging.error("Bad message (msgid={}, seqno={}, error={}): msg_seqno too high (similarly, there is a message with a higher msg_id but with either a lower or an equal and odd seqno)".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 34:
            logging.error("Bad message (msgid={}, seqno={}, error={}): an even msg_seqno expected (irrelevant message), but odd received".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 35:
            logging.error("Bad message (msgid={}, seqno={}, error={}): odd msg_seqno expected (relevant message), but even received".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 48:
            logging.error("Bad message (msgid={}, seqno={}, error={}): incorrect server salt (in this case, the bad_server_salt response is received with the correct salt, and the message is to be re-sent with it)".format(bad_msg_id, bad_msg_seqno, error_code))
        elif error_code == 64:
            logging.error("Bad message (msgid={}, seqno={}, error={}): invalid container.".format(bad_msg_id, bad_msg_seqno, error_code))
        return True
    
    def process_msgs_ack(self, msg_ids):
        logging.debug("process_msgs_ack(msg_ids={}):".format(msg_ids))
        # TODO: отметить сообщения как полученные
        return True
    
    def process_rpc_result(self, req_msg_id, result):
        logging.debug("process_rpc_result(req_msg_id={}, result={})".format(req_msg_id, result))
        return True
    
    def process_rpc_error(self, error_code, error_message):
        logging.debug("process_rpc_error(error_code={}, error_message={})".format(error_code, error_message))
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

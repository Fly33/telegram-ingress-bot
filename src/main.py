# -*- coding: utf8 -*-
import logging
import logging.handlers
import traceback
import yaml
import re
from argparse import ArgumentParser
from time import time as Now
from collections import OrderedDict
from select import select
import threading
import platform
import sys
import datetime

import rsa
from Crypto.Cipher import XOR
from Crypto.Random import random

from crypto import *
from format import *
from session import CryptoSession
from algorithm import *
from error import *
import timer
from config import Config

VERSION = '1.0.0'

TRACE = 5

class DataSession(CryptoSession):
    def __init__(self):
        super().__init__()

    def Receive(self, timeout):
        message = super().Receive(timeout)
        if message is None:
            return None
        id, seq, data = message
        logging.log(TRACE, "Recv data: {}".format(self.Hex(data)))
        return (id, seq, Box.Parse(data)[0])

    def Send(self, message_id, seq_no, data, encrypted=True):
        data = Box.Dump(data)
        logging.log(TRACE, "Send data: {}".format(self.Hex(data)))
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


class DataCenter:
    def __init__(self, id, config, public_key, on_ready): # TODO: выпилить application
        self.id = id
        self.ping_timer_id = timer.New()
        self.salt_timer_id = timer.New()
        self.message_id = 0
        self.n_relevant = 0
        self.time_offset = 0
        self.queue = []
        self.acks = []
        self.sent_messages = OrderedDict()
        self.rpc = {}
        self.session = DataSession()
        self.config = config
        self.public_key = public_key
        self.ready = False
        self.on_ready = on_ready

    def Connect(self, test=False):
        host = self.config['host']
        port = self.config['port']
        self.session.Connect(host, port)

        if test or 'auth_key' not in self.config:
            logging.info("Generating new auth key.")
            self.retry_id = 0
            self.nonce = random.getrandbits(128)
            self.Send(req_pq.Create(self.nonce), False, False)
        else:
            self.session.auth_key = self.config['auth_key']
            logging.info("Auth key is loaded.")
            self.Send(get_future_salts.Create(1), relevant=False)

    def fileno(self):
        return self.session.fileno()

    def process(self):
        message = self.session.Receive(0)
        if message is not None:
            self.Dispatch(*message)

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
        logging.debug("Sending message: dc={}, msgid={}, seqno={}, data={}".format(self.id, msg_id, seq_no, data))
        timer.Set(self.ping_timer_id, Now() + 1, 0, self.Send, ping.Create(random.getrandbits(64)), relevant=False)
        return self.session.Send(msg_id, seq_no, data, encrypted)

    def Send(self, data, relevant=True, encrypted=True):
        msg_id = self.getMessageId()
        seq_no = self.getSeqNo(relevant)
        return self._Queue(msg_id, seq_no, data, relevant, encrypted)

    def _Queue(self, msg_id, seq_no, data, relevant, encrypted):
        logging.debug("Queueing message: dc={}, msgid={}, seqno={}, data={}".format(self.id, msg_id, seq_no, data))
        if relevant:
            self.sent_messages[msg_id] = data
        if encrypted:
            self.queue.append((msg_id, seq_no, data))
            return
        return self._Send(msg_id, seq_no, data, encrypted)

    def Call(self, data, callback, *args, **kwargs):
        msg_id = self.getMessageId()
        seq_no = self.getSeqNo(True)
        self.rpc[msg_id] = (data, callback, args, kwargs)
        return self._Queue(msg_id, seq_no, data, True, True)

    def Flush(self):
        if self.acks:
            self.Send(msgs_ack.Create(self.acks), relevant=False)
            self.acks = []
        # TODO: переслать сообщения, ответ на которые не получен
        if not self.queue:
            return
        if len(self.queue) == 1:
            msg_id, seq_no, data = self.queue[0]
        else:
            msg_id, seq_no, data = self.getMessageId(), self.getSeqNo(False), msg_container.Create(tuple(message.Create(msg_id, seq_no, data) for msg_id, seq_no, data in self.queue))
        self.queue = []
        return self._Send(msg_id, seq_no, data)

    def Dispatch(self, msg_id, seq_no, data):
        logging.debug("Received message: dc={}, msgid={}, seqno={}, data={}".format(self.id, msg_id, seq_no, data))
        getattr(self, 'process_' + data.Name(), self.process_unknown)(msg_id, seq_no, data)

    def Ack(self, msg_id):
        self.acks.append(msg_id)

    def process_unknown(self, msg_id, seq_no, data):
        logging.error("There is no handle for message \"{}\"".format(data.Name()))

    def process_resPQ(self, msg_id, seq_no, data):
        if data.nonce != self.nonce:
            raise SecurityError('data.nonce != self.nonce')
        self.server_nonce = data.server_nonce

        p, q = Decompose(data.pq)

        server_public_key = rsa.PublicKey.load_pkcs1(self.public_key)
        # проверить отпечаток
        sha = SHA1(rsa_public_key.Dump(rsa_public_key.Create(server_public_key.n, server_public_key.e)))
        logging.debug('Server public fingerprint: {}'.format(Hex(sha)))
        for fp_id, fp in enumerate(data.server_public_key_fingerprints):
            if fp == int.from_bytes(sha[-8:], 'little'):
                fingerprint_id = fp_id
                break
        else:
            raise SecurityError('Server public key doesn\'t correspond to the given fingerprints.')
        self.new_nonce = random.getrandbits(256)
        inner_data = Box.Dump(p_q_inner_data.Create(data.pq, p, q, data.nonce, data.server_nonce, self.new_nonce))
        inner_data = SHA1(inner_data) + inner_data
        inner_data = inner_data + random.getrandbits((255 - len(inner_data))*8).to_bytes(255 - len(inner_data), 'big')
        encrypted_data = pow(int.from_bytes(inner_data, 'big'), server_public_key.e, server_public_key.n).to_bytes(256, 'big')
        self.Send(req_DH_params.Create(data.nonce, data.server_nonce, p, q, data.server_public_key_fingerprints[fingerprint_id], encrypted_data), False, False)

    def process_server_DH_params_fail(self, msg_id, seq_no, data):
        pass

    def process_server_DH_params_ok(self, msg_id, seq_no, data):
        if data.nonce != self.nonce:
            raise SecurityError('data.nonce != self.nonce')
        if data.server_nonce != self.server_nonce:
            raise SecurityError('data.server_nonce != self.server_nonce')

        server_nonce_str = Int128.Dump(data.server_nonce)
        new_nonce_str = Int256.Dump(self.new_nonce)
        sn_nn = SHA1(server_nonce_str + new_nonce_str)
        nn_sn = SHA1(new_nonce_str + server_nonce_str)
        nn_nn = SHA1(new_nonce_str + new_nonce_str)
        tmp_aes_key = nn_sn + sn_nn[0:12]
        tmp_aes_iv = sn_nn[12:20] + nn_nn + new_nonce_str[0:4]

        self.aes_ige = AES_IGE_TLG(tmp_aes_key, tmp_aes_iv)
        answer = self.aes_ige.decrypt(data.encrypted_answer)

        self.Dispatch(msg_id, seq_no, answer)

    def process_server_DH_inner_data(self, msg_id, seq_no, data):
        if data.nonce != self.nonce:
            raise SecurityError('data.nonce != self.nonce')
        if data.server_nonce != self.server_nonce:
            raise SecurityError('data.server_nonce != self.server_nonce')

        self.time_offset = data.server_time - Now()

        b = random.getrandbits(2048)
        g_b = pow(data.g, b, data.dh_prime)
        g_ab = pow(data.g_a, b, data.dh_prime)

        self.session.auth_key = g_ab.to_bytes(256, 'big')

        encrypted_data = self.aes_ige.encrypt(client_DH_inner_data.Create(data.nonce, data.server_nonce, self.retry_id, g_b))
        self.retry_id += 1
        self.Send(set_client_DH_params.Create(data.nonce, data.server_nonce, encrypted_data), False, False)

    def process_dh_gen_ok(self, msg_id, seq_no, data):
        if data.nonce != self.nonce:
            raise SecurityError('data.nonce != self.nonce')
        if data.server_nonce != self.server_nonce:
            raise SecurityError('data.server_nonce != self.server_nonce')
        # TODO: проверить хэш
        self.config['auth_key'] = self.session.auth_key
        self.config.save()
        self.session.salt = XOR.new(self.new_nonce.to_bytes(32, 'little')[0:8]).encrypt(self.server_nonce.to_bytes(16, 'little')[0:8])
        del self.nonce
        del self.server_nonce
        del self.new_nonce
        del self.retry_id
        del self.aes_ige
        logging.info("Auth key was successfully generated.")

        self.Send(get_future_salts.Create(1), relevant=False)

    def process_dh_gen_retry(self, msg_id, seq_no, data):
        # TODO: попробовать снова
        pass

    def process_dh_gen_fail(self, msg_id, seq_no, data):
        # TODO: попробовать снова
        pass

    def process_future_salts(self, msg_id, seq_no, data):
        self.time_offset = data.now - Now()
        for future_salt in data.salts:
            logging.info("Salt: {}; Valid: {} - {}".format(future_salt.salt, datetime.datetime.fromtimestamp(future_salt.valid_since), datetime.datetime.fromtimestamp(future_salt.valid_until)))
        self.session.salt = Long.Dump(data.salts[0].salt)
        timer.Set(self.salt_timer_id, future_salt.valid_until, 0, lambda: self.Send(get_future_salts.Create(1), relevant=False))
        if not self.ready:
            self.ready = True
            self.on_ready()

    def process_ping(self, msg_id, seq_no, data):
        self.Send(pong.Create(self.message_id, data.ping_id), relevant=False)

    def process_pong(self, msg_id, seq_no, data):
        pass

    def process_msg_container(self, msg_id, seq_no, data):
        for message in data.messages:
            self.Dispatch(message.msg_id, message.seqno, message.body)

    def process_new_session_created(self, msg_id, seq_no, data):
        self.session.salt = Long.Dump(data.server_salt)
        self.session.message_id = data.first_msg_id
        self.Ack(msg_id)

    def process_bad_msg_notification(self, msg_id, seq_no, data):
        error_str = {
            16: "msg_id too low (most likely, client time is wrong; it would be worthwhile to synchronize it using msg_id notifications and re-send the original message with the “correct” msg_id or wrap it in a container with a new msg_id if the original message had waited too long on the client to be transmitted)",
            17: "msg_id too high (similar to the previous case, the client time has to be synchronized, and the message re-sent with the correct msg_id)",
            18: "incorrect two lower order msg_id bits (the server expects client message msg_id to be divisible by 4)",
            19: "container msg_id is the same as msg_id of a previously received message (this must never happen)",
            20: "message too old, and it cannot be verified whether the server has received a message with this msg_id or not",
            32: "msg_seqno too low (the server has already received a message with a lower msg_id but with either a higher or an equal and odd seqno)",
            33: "msg_seqno too high (similarly, there is a message with a higher msg_id but with either a lower or an equal and odd seqno)",
            34: "an even msg_seqno expected (irrelevant message), but odd received",
            35: "odd msg_seqno expected (relevant message), but even received",
            48: "incorrect server salt (in this case, the bad_server_salt response is received with the correct salt, and the message is to be re-sent with it)",
            64: "invalid container.",
        }
        logging.error("Bad message (msgid={}, seqno={}, error={}): {}".format(data.bad_msg_id, data.bad_msg_seqno, data.error_code, error_str[data.error_code] if data.error_code in error_str else "<unknown>"))

    def process_bad_server_salt(self, msg_id, seq_no, data):
        #bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long
        self.session.salt = Long.Dump(data.new_server_salt)
        self.Send(get_future_salts.Create(1), relevant=False)
        if data.bad_msg_id in self.sent_messages:
            self.Send(msg_copy.Create(message.Create(data.bad_msg_id, data.bad_msg_seqno, self.sent_messages[data.bad_msg_id])))

    def process_msgs_ack(self, msg_id, seq_no, data):
        # TODO: отметить сообщения как полученные
        for msg_id in data.msg_ids:
            if msg_id in self.sent_messages:
                del self.sent_messages[msg_id]
            else:
                logging.error("Unknown ack msg_id: {}".format(msg_id))

    def process_rpc_result(self, msg_id, seq_no, data):
        self.Ack(msg_id)
        if data.req_msg_id in self.sent_messages:
            del self.sent_messages[data.req_msg_id]
        else:
            logging.error("Unknown ack msg_id: {}".format(data.req_msg_id))
        if data.req_msg_id not in self.rpc:
            logging.error("Unknown rpc msg_id: {}".format(data.req_msg_id))
            return
        req_data, callback, args, kwargs = self.rpc[data.req_msg_id]
        del self.rpc[data.req_msg_id]
        return callback(req_data, data.result, *args, **kwargs)


class ApplicationDataCenter(DataCenter):
    def __init__(self, id, application, config, public_key):
        self.application = application
        self.rpc_queue = []
        self._authorised = True
        super().__init__(id, config, public_key, self.dc_ready)

    def get_authorised(self):
        return self._authorised

    def set_authorised(self, authorised):
        self._authorised = authorised
        if authorised:
            self.rpc_flush()

    def rpc_flush(self):
        for request in self.rpc_queue:
            super().Call(request, self.rpc_callback)

    authorised = property(get_authorised, set_authorised)

    def Call(self, request):
        # TODO: отложить запросы до возможности их исполнения
        if not self.ready or not self.authorised and request.Name() not in ('auth_sendCode', 'auth_sendCall', 'auth_checkPhone', 'auth_signUp', 'auth_signIn', 'auth_importAuthorization', 'help_getConfig', 'help_getNearestDc'):
            self.rpc_queue.append(request)
            return
        if self.first:
            request = invokeWithLayer.Create(23, initConnection.Create(self.application.config['api_id'], platform.platform(), sys.version, VERSION, self.application.config.get('lang_code', 'en'), request))
            self.first = False
        return super().Call(request, self.rpc_callback)

    def rpc_callback(self, req, res):
        return self.application.rpc_callback(self, req, res)

    def Connect(self, test=False):
        self.first = True
        return super().Connect(test=test)

    def dc_ready(self):
        self.rpc_flush()
        return self.application.dc_ready(self)


class InputThread(threading.Thread):
    def __init__(self, prompt, callback):
        self.result = None
        self.prompt = prompt
        self.callback = callback
        super().__init__()

    def run(self):
        self.result = input(self.prompt)

    def start(self):
        super().start()
        self.timer_callback(timer.New())

    def timer_callback(self, timer_id):
        self.join(0)
        if self.is_alive():
            timer.Set(timer_id, Now() + 1, 0, self.timer_callback, timer_id)
            return
        self.callback(self.result)


def Input(prompt, callback):
    input_thread = InputThread(prompt, callback)
    input_thread.start()


class Telegram:
    def __init__(self, config):
        self.config = config
        self.data_centers = {}
        self.ready = False
        self.nearest_dc = None

    def Run(self):
        # перенести?
        try:
            with open(self.config["public_key"], 'rb') as f:
                self.public_key = f.read()
        except:
            logging.exception('Server public key is missing!')
            return
        
        dc_id = list(self.config['data_centers'].keys())[0]
        data_center = ApplicationDataCenter(dc_id, self, self.config['data_centers'][dc_id], self.public_key);
        self.data_centers[dc_id] = data_center
        data_center.Connect(self.config['test'])

        while True:
            try:
                for data_center in self.data_centers.values():
                    data_center.Flush()
                data_centers, _, _ = select(self.data_centers.values(), (), (), timer.GetTimeout())
                for data_center in data_centers:
                    data_center.process()
                timer.Process()
            except ConnectionError:
                # TODO: reconnect
                break
            except:
                logging.exception("The game is up!")
                break # TODO: может что-нить поумнее сделать?

    def dc_ready(self, dc):
        if not self.ready:
            dc.Call(help_getConfig.Create())

    def data_center(self, dc_id):
        if dc_id not in self.data_centers:
            if dc_id not in self.config['data_centers']:
                logging.error('Data center #{} is not found'.format(dc_id))
                return
            data_center = ApplicationDataCenter(dc_id, self, self.config['data_centers'][dc_id], self.public_key)
            self.data_centers[dc_id] = data_center
            data_center.Connect(self.config['test'])
        return self.data_centers[dc_id]

    def rpc_callback(self, dc, request, result):
        if result.Name() == 'rpc_error':
            error_handler = getattr(self, 'rpc_' + request.Name() + '_result_' + str(result.error_code), None) 
            if error_handler: 
                return error_handler(dc, request, result)
            elif result.error_code == 303: # ERROR_SEE_OTHER
                match = re.match(r'(\w+?(\d+))(?:: (.+))?', result.error_message)
                if match:
                    dc_id = int(match.group(2))
                    return self.data_center(dc_id).Call(request)
                else:
                    logging.error('Unable to parse 303 error: {}'.format(result.error_message))
                    return
            elif result.error_code == 401: # UNAUTHORIZED
                # TODO: проверить, что авторизация ещё не начата
                dc.authorised = False
                dc.Call(request) # TODO: перепостить запрос
                if dc.id != self.nearest_dc:
                    return self.data_center(self.nearest_dc).Call(auth_exportAuthorization.Create(dc.id))
                if 'api_id' not in self.config or 'api_hash' not in self.config:
                    logging.error("Get api_id and api_hash from https://my.telegram.org/apps")
                    return
                if 'profile' not in self.config or 'phone_number' not in self.config['profile']:
                    logging.error('The config does not contain phone number')
                    return
                return dc.Call(auth_sendCode.Create(self.config['profile']['phone_number'], 0, int(self.config['api_id']), self.config['api_hash'], self.config.get('lang_code', 'en')))
            else:
                logging.error('Unhandled rpc error for "{}": {} {}'.format(request.Name(), result.error_code, result.error_message))
                return
        return getattr(self, 'rpc_' + request.Name() + '_result_' + result.Name(), self.rpc_unknown)(dc, request, result)

    def rpc_unknown(self, dc, request, result):
        logging.error("There is no handler for request \"{}\" with result \"{}\"".format(request.Name(), result.Name()))

    def rpc_help_getConfig_result_config(self, dc, request, result):
        for dc_option in result.dc_options:
            if dc_option.id not in self.config['data_centers']: 
                host = dc_option.hostname if dc_option.hostname else dc_option.ip_address
                self.config['data_centers'][dc_option.id] = {'host': host, 'port': dc_option.port}
        self.config.save()
        dc.Call(help_getNearestDc.Create())

    def rpc_help_getNearestDc_result_nearestDc(self, dc, request, result):
        self.nearest_dc = result.nearest_dc
        self.ready = True
        dc.Call(account_updateStatus.Create(False))

    def rpc_auth_sendCode_result_auth_sentCode(self, dc, request, result):
        if result.phone_registered:
            Input('Enter confirmation code: ', lambda phone_code: dc.Call(auth_signIn.Create(self.config['profile']['phone_number'], result.phone_code_hash, phone_code)))
        else:
            Input('Enter confirmation code: ', lambda phone_code: dc.Call(auth_signUp.Create(self.config['profile']['phone_number'], result.phone_code_hash, phone_code, self.config['profile'].get('first_name', 'Unknown'), self.config['profile'].get('last_name', 'Bot'))))

    def rpc_auth_exportAuthorization_result_auth_exportedAuthorization(self, dc, request, result):
        self.data_centers[request.dc_id].Call(auth_importAuthorization.Create(result.id, result.bytes))

    def rpc_auth_signIn_result_auth_authorization(self, dc, request, result):
        dc.authorised = True

    def rpc_auth_signUp_result_auth_authorization(self, dc, request, result):
        dc.authorised = True

    def rpc_auth_importAuthorization_result_auth_authorization(self, dc, request, result):
        dc.authorised = True


def main():
    parser = ArgumentParser()
    parser.add_argument("-c", "--config", help="yaml config file name", default="config.yaml")
    args = parser.parse_args()

    config = Config()
    try:
        config.load(args.config)
    except:
        logging.error('Unable to open "{}" file.'.format(options.config))
        return

    level = TRACE
    logging.addLevelName(TRACE, "TRACE")
    logger = logging.getLogger()
    logger.setLevel(level)
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    handler = logging.handlers.RotatingFileHandler(config["log"], maxBytes=16000000, backupCount=2)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(level)
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

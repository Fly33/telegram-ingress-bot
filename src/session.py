# -*- coding: utf8 -*-
import logging
from time import time
from socket import socket
from select import select
from crypto import CRC32

class ConnectionError(RuntimeError):
    pass

class TcpSession:
    def __init__(self):
        self.client_seq = 0
        self.data = b''
    
    def Connect(self, host, port):
        self.sock = socket()
        self.sock.connect((host, port))
    
    def Receive(self, timeout):
        if len(self.data) < 4 or len(self.data) < int.from_bytes(self.data[:4], 'little'):
            rlist, _, _ = select((self.sock,), (), (), timeout)
            if len(rlist) == 0:
                return
            data = self.sock.recv(4096)
            if len(data) == 0:
                raise ConnectionError("Connection closed")
            self.data += data
        data_len = int.from_bytes(self.data[:4], 'little')
        if len(self.data) < data_len:
            return
        data = self.data[0:data_len]
        self.data = self.data[data_len:]
        if int.from_bytes(data[-4:], 'little') != CRC32(data[:-4]):
            return
        seq = int.from_bytes(data[4:8], 'little')
        self.server_seq = seq
        return data[8:-4]
    
    def Send(self, data):
        length = len(data) + 12
        data = length.to_bytes(4, "little") + self.client_seq.to_bytes(4, "little") + data
        data = data + CRC32(data).to_bytes(4, "little")
        self.client_seq += 1
        # TODO: сделать отложенную отправку
        while len(data) != 0:
            ln = self.sock.send(data)
            data = data[ln:]

class CryptoSession(TcpSession):
    def __init__(self):
        TcpSession.__init__(self)
        self.message_id = 0
        self.time_offset = 0
    
    def getMessageId(self):
        msg_id = int((time() + self.time_offset)  * (1 << 30)) * 4
        if self.message_id >= msg_id:
            self.message_id += 4
        else:
            self.message_id = msg_id
        return self.message_id
    
    def Receive(self, timeout):
        data = super().Receive(timeout)
        if data is None:
            return None
        logging.debug("Recv data: {}".format(self.Hex(data)))
        auth_key_id = data[0:8]
        if auth_key_id == b'\0\0\0\0\0\0\0\0':
            message_id = data[8:16]
            message_len = int.from_bytes(data[16:20], 'little')
            return data[20:]
        else:
            pass
        
    def Send(self, data, encrypted=True):
        if encrypted:
            pass
        else:
            data = b'\0\0\0\0\0\0\0\0' + self.getMessageId().to_bytes(8, "little") + len(data).to_bytes(4, "little") + data
        logging.debug("Send data: {}".format(self.Hex(data)))
        return super().Send(data)
    
    def __setattr__(self, name, value):
        if name == "auth_key":
            self.auth_key_id = SHA1(self.auth_key)[-8:]
        return super().__setattr__(name, value)
    
    def Hex(self, data):
        return ''.join(('\n\t{:03x}0 |'.format(i) + ''.join((' {:02x}'.format(int.from_bytes(data[i*16+j:i*16+j+1], 'big')) for j in range(16) if i*16+j < len(data))) for i in range((len(data)-1)//16+1)))


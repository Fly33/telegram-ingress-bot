# -*- coding: utf8 -*-
import logging
import struct

class Type:
    def __init__(self, name):
        self.name = name

class Int(Type):
    size = 4
    
    @classmethod
    def Parse(cls, data, offset=0):
        return (int.from_bytes(data[offset:offset+cls.size], 'little'), cls.size)
    
    @classmethod
    def Dump(cls, value):
        return value.to_bytes(cls.size, 'little')

class Long(Int):
    size = 8

class Int128(Int):
    size = 16

class Int256(Int):
    size = 32

class String(Type):
    @classmethod
    def Parse(cls, data, offset=0):
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
    
class BigInt(String):
    @classmethod
    def Parse(cls, data, offset=0):
        result, ln = super().Parse(data, offset)
        return (int.from_bytes(result, 'big'), ln)
    
    @classmethod
    def Dump(cls, value):
        return super().Dump(value.to_bytes((value.bit_length() - 1) // 8 + 1, 'big'))

class Double(Type):
    @classmethod
    def Parse(cls, data, offset=0):
        return (struct.unpack_from('d', data, offset)[0], 8)
    
    @classmethod
    def Dump(cls, value):
        return struct.pack('d', value)

def Tuple(*class_arg):
    class tuple_cl(Type):
        @classmethod
        def Parse(cls, data, offset=0):
            result = []
            reslen = 0
            for t in class_arg:
                dt, ln = t.Parse(data, offset+reslen)
                result.append(dt)
                reslen += ln
            return (tuple(result), reslen)
        
        @classmethod
        def Dump(cls, values):
#             if len(values) == 1 and isinstance(values[0], tuple):
#                 return cls.Dump(*values[0])
            result = b''
            for arg, value in zip(class_arg, values):
                result += arg.Dump(value)
            return result
        
    return tuple_cl

def Vector(tipe):
    class vector_cl(Type):
        @classmethod
        def Parse(cls, data, offset=0):
            result = []
            reslen = 0
            count, ln = Int.Parse(data, offset+reslen)
            reslen += ln
            for _ in range(count):
                dt, ln = tipe.Parse(data, offset+reslen)
                result.append(dt)
                reslen += ln
            return (tuple(result), reslen)
        
        @classmethod
        def Dump(cls, value):
            result = Int.Dump(len(value))
            for val in value:
                result += tipe.Dump(val)
            return result
                
    return vector_cl

def VectorBox(tipe):
    class vector_cl(Vector(tipe)):
        @classmethod
        def Parse(cls, data, offset=0):
            reslen = 0
            _, ln = Int.Parse(data, offset+reslen) # 0x1cb5c415
            reslen += ln
            result, ln = super().Parse(data, offset+reslen)
            reslen += ln
            return (result, reslen)
        
        @classmethod
        def Dump(cls, value):
            result = Int.Dump(0x1cb5c415)
            result += super().Dump(value)
            return result
    
    return vector_cl

class BoxType(type):
    def __init__(self, *args, **kwargs):
        self.dict = {}
        super().__init__(*args, **kwargs)
    def __getitem__(self, key):
        return self.dict[key]
    def __contains__(self, key):
        return key in self.dict
    def __setitem__(self, key, value):
        self.dict[key] = value

class Box(Type, metaclass=BoxType):
    @classmethod
    def Parse(cls, data, offset=0):
        tipe, ln = Int.Parse(data, offset)
        if tipe not in cls:
            raise KeyError("Unknown hash id {:x}".format(tipe))
        data, data_len = cls[tipe].Parse(data, offset+ln)
        return (data, ln + data_len)
    
    @classmethod
    def Dump(cls, value):
        return Int.Dump(value.Hash()) + cls[value.Hash()].Dump(value)

    @classmethod
    def Register(cls, name, hash, *types):
        class struct:
            def __init__(self, dict):
                for key, value in dict.items():
                    setattr(self, key, value)
            
            def Name(self):
                return name
            
            def Hash(self):
                return hash
            
            def items(self):
                return ((tipe.name, getattr(self, tipe.name)) for tipe in types)
            
            @classmethod
            def hex(cls, data):
                if isinstance(data, int):
                    return hex(data)[2:]
                elif isinstance(data, tuple) or isinstance(data, list):
                    return str(tuple(cls.hex(x) for x in data))
                elif isinstance(data, bytes):
                    return hex(int.from_bytes(data, 'big'))[2:]
                else:
                    return data
            
            def __str__(self):
                return '{}({})'.format(self.Name(), ', '.join('{}={}'.format(key, self.hex(value)) for key, value in self.items()))

            def __repr__(self):
                return self.__str__()
        
        class struct_cl(Tuple(*types)):
            @classmethod
            def Name(cls):
                return name
            
            @classmethod
            def Hash(cls):
                return hash
            
            @classmethod
            def Create(cls, *values):
                return struct({tipe.name: value for tipe, value in zip(types, values)})
            
            @classmethod
            def Parse(cls, data, offset=0):
                data, ln = cls.__bases__[0].Parse(data, offset)
                return (cls.Create(*data), ln)
            
            @classmethod
            def Dump(cls, value):
                return cls.__bases__[0].Dump(tuple(getattr(value, tipe.name) for tipe in types))

        while cls != Type:    
            cls[hash] = struct_cl
            cls[name] = struct_cl
            cls = cls.__bases__[0]
        globals()[name] = struct_cl

class MesuredBox(Box):
    @classmethod
    def Parse(cls, data, offset=0):
        _, ln = Int.Parse(data, offset)
        data, data_len = Box.Parse(data, offset+ln)
        return (data, ln + data_len)
    
    @classmethod
    def Dump(cls, value):
        data = Box.Dump(value)
        return Int.Dump(len(data)) + data

class Bool(Box, metaclass=BoxType):
    pass

Box.Register('resPQ', 0x05162463, Int128('nonce'), Int128('server_nonce'), BigInt('pq'), VectorBox(Long)('server_public_key_fingerprints'))
Box.Register('server_DH_params_fail', 0x79cb045d, Int128('nonce'), Int128('server_nonce'), Int128('new_nonce_hash'))
Box.Register('server_DH_params_ok', 0xd0e8075c, Int128('nonce'), Int128('server_nonce'), String('encrypted_answer'))
Box.Register('server_DH_inner_data', 0xb5890dba, Int128('nonce'), Int128('server_nonce'), Int('g'), BigInt('dh_prime'), BigInt('g_a'), Int('server_time'))
Box.Register('dh_gen_ok', 0x3bcbf734, Int128('nonce'), Int128('server_nonce'), Int128('new_nonce_hash1'))
Box.Register('dh_gen_retry', 0x46dc1fb9, Int128('nonce'), Int128('server_nonce'), Int128('new_nonce_hash2'))
Box.Register('dh_gen_fail', 0xa69dae02, Int128('nonce'), Int128('server_nonce'), Int128('new_nonce_hash3'))
Box.Register('req_pq', 0x60469778, Int128('nonce'))
Box.Register('p_q_inner_data', 0x83c95aec, BigInt('pq'), BigInt('p'), BigInt('q'), Int128('nonce'), Int128('server_nonce'), Int256('new_nonce'))
Box.Register('req_DH_params', 0xd712e4be, Int128('nonce'), Int128('server_nonce'), BigInt('p'), BigInt('q'), Long('public_key_fingerprint'), String('encrypted_data'))
Box.Register('rsa_public_key', 0x7a19cb76, BigInt('n'), BigInt('e'))
Box.Register('set_client_DH_params', 0xf5045f1f, Int128('nonce'), Int128('server_nonce'), String('encrypted_data'))
Box.Register('client_DH_inner_data', 0x6643b654, Int128('nonce'), Int128('server_nonce'), Long('retry_id'), BigInt('g_b'))
Box.Register('ping', 0x7abe77ec, Long('ping_id'))
Box.Register('pong', 0x347773c5, Long('msg_id'), Long('ping_id'))
Box.Register('message', 0x5bb8e511, Long('msg_id'), Int('seqno'), MesuredBox('body'))
Box.Register('msg_container', 0x73f1f8dc, Vector(message)('messages'))
Box.Register('new_session_created', 0x9ec20908, Long('first_msg_id'), Long('unique_id'), Long('server_salt'))
Box.Register('bad_msg_notification', 0xa7eff811, Long('bad_msg_id'), Int('bad_msg_seqno'), Int('error_code'))
Box.Register('msgs_ack', 0x62d6b459, VectorBox(Long)('msg_ids'))
Bool.Register('boolFalse', 0xbc799737)
Bool.Register('boolTrue', 0x997275b5)
Box.Register('error', 0xc4b9f9bb, Int('code'), String('text'))
Box.Register('null', 0x56730bcc)
Box.Register('rpc_result', 0xf35c6d01, Long('req_msg_id'), Box('result'))
Box.Register('rpc_error', 0x2144ca19, Int('error_code'), String('error_message'))
Box.Register('dcOption', 0x2ec2a43c, Int('id'), String('hostname'), String('ip_address'), Int('port'))
Box.Register('disabledFeature', 0xae636f24, String('feature'), String('description'))
Box.Register('config', 0x232d5905, Int('date'), Bool('test_mode'), Int('this_dc'), VectorBox(Box)('dc_options'), Int('chat_size_max'))
Box.Register('config', 0x2e54dd74, Int('date'), Bool('test_mode'), Int('this_dc'), VectorBox(Box)('dc_options'), Int('chat_size_max'), Int('broadcast_size_max'))
Box.Register('config', 0x7dae33e0, Int('date'), Int('expires'), Bool('test_mode'), Int('this_dc'), VectorBox(Box)('dc_options'), Int('chat_big_size'), Int('chat_size_max'), Int('broadcast_size_max'), VectorBox(Box)('disabled_features'))
Box.Register('help_getConfig', 0xc4f9186b)
Box.Register('nearestDc', 0x8e1a1775, String('country'), Int('this_dc'), Int('nearest_dc'))
Box.Register('help_getNearestDc', 0x1fb33026)

if __name__ == "__main__":
    Register("test_struct", 0x12345678, Int, Int)

    test_cl = StructByName['test_struct']
    t = test_cl()
    data = Box.Dump(t.Create(123, 456))
    print(hex(int.from_bytes(data, 'big'))[2:].upper())
    x, ln = Box.Parse(data)
    print(x)
    

# -*- coding: utf8 -*-
import logging
import struct

def Int(base_size=32):
    assert(base_size % 8 == 0)
    base_size //= 8
    
    class int_cl:
        size = base_size
        
        @classmethod
        def Parse(cls, data, offset=0):
            return (int.from_bytes(data[offset:offset+cls.size], 'little'), cls.size)
        
        @classmethod
        def Dump(cls, value):
            return value.to_bytes(cls.size, 'little')
        
        Int = staticmethod(Int)
        def __new__(cls, size=32):
            return cls.Int(size)
    
    return int_cl

Int = Int()

class Long(Int(64)):
    pass

class String:
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

class Double:
    @classmethod
    def Parse(cls, data, offset=0):
        return (struct.unpack_from('d', data, offset)[0], 8)
    
    @classmethod
    def Dump(cls, value):
        return struct.pack('d', value)

def Tuple(*class_arg):
    class tuple_cl:
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

StructById = {}
StructByName = {}

def Register(name, hash, *args):
    class struct_cl(Tuple(*args)):
        @classmethod
        def Name(cls):
            return name
        
        @classmethod
        def Hash(cls):
            return hash
        
        @classmethod
        def Create(cls, *args):
            # TODO: вставить проверку типов?
            return (hash,) + args

    StructById[hash] = struct_cl
    StructByName[name] = struct_cl
    globals()[name] = struct_cl

class Box:
    @classmethod
    def Parse(cls, data, offset=0):
        tipe, ln = Int.Parse(data, offset)
        if tipe not in StructById:
            raise KeyError("Unknown hash id {:x}".format(tipe))
        data, data_len = StructById[tipe].Parse(data, offset+ln)
        return ((tipe,) + data, ln + data_len)
    
    @classmethod
    def Dump(cls, *values):
        if len(values) == 1 and isinstance(values[0], tuple):
            return cls.Dump(*values[0])
        return Int.Dump(values[0]) + StructById[values[0]].Dump(*values[1:])

class MesuredBox(Box):
    @classmethod
    def Parse(cls, data, offset=0):
        _, ln = Int.Parse(data, offset)
        data, data_len = Box.Parse(data, offset+ln)
        return (data, ln + data_len)
    
    @classmethod
    def Dump(cls, *values):
        data = Box.Dump(*values)
        return Int.Dump(len(data)) + data

Register('resPQ', 0x05162463, Int(128), Int(128), BigInt, VectorBox(Long))
Register('server_DH_params_fail', 0x79cb045d, Int(128), Int(128), Int(128)) 
Register('server_DH_params_ok', 0xd0e8075c, Int(128), Int(128), String)
Register('server_DH_inner_data', 0xb5890dba, Int(128), Int(128), Int, BigInt, BigInt, Int) 
Register('dh_gen_ok', 0x3bcbf734, Int(128), Int(128), Int(128))
Register('dh_gen_retry', 0x46dc1fb9, Int(128), Int(128), Int(128))
Register('dh_gen_fail', 0xa69dae02, Int(128), Int(128), Int(128))
Register('req_pq', 0x60469778, Int(128))
Register('p_q_inner_data', 0x83c95aec, BigInt, BigInt, BigInt, Int(128), Int(128), Int(256))
Register('req_DH_params', 0xd712e4be, Int(128), Int(128), BigInt, BigInt, Long, String)
Register('rsa_public_key', 0x7a19cb76, BigInt, BigInt)
Register('set_client_DH_params', 0xf5045f1f, Int(128), Int(128), String)
Register('client_DH_inner_data', 0x6643b654, Int(128), Int(128), Long, BigInt)
Register('ping', 0x7abe77ec, Long)
Register('pong', 0x347773c5, Long, Long)
Register('message', 0x5bb8e511, Long, Int, MesuredBox)
Register('msg_container', 0x73f1f8dc, Vector(message))
Register('new_session_created', 0x9ec20908, Long, Long, Long)
Register('bad_msg_notification', 0xa7eff811, Long, Int, Int)
Register('msgs_ack', 0x62d6b459, VectorBox(Long))

if __name__ == "__main__":
    Register("test_struct", 0x12345678, Int, Int)

    test_cl = StructByName['test_struct']
    t = test_cl()
    data = Box.Dump(t.Create(123, 456))
    print(hex(int.from_bytes(data, 'big'))[2:].upper())
    x, ln = Box.Parse(data)
    print(x)
    

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
    
def BigInt(size):
    assert(size % 8 == 0)
    size //= 8
    class big_int_cl(String):
        @classmethod
        def Parse(cls, data, offset):
            result, ln = super().Parse(data, offset)
            return (int.from_bytes(result, 'big'), ln)
        @classmethod
        def Dump(cls, value):
            return super().Dump(value.to_bytes(size, 'big'))
    return big_int_cl

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

StructById = {}
StructByName = {}

def Struct(name, hash, **kwarg):
    def Data(name):
        class data_cl:
            def __init__(self, **kwarg):
                for k, v in kwarg.items():
                    setattr(self, k, v)
                    
            @classmethod
            def Name(cls):
                return name

        return data_cl
    
    class struct_cl(Tuple(Int(), *kwarg.values())):
        @classmethod
        def Parse(cls, data, offset=0):
            result, ln = super().Parse(data, offset)
            return (Data(name)(**dict(zip(kwarg.keys(), result[1:]))), ln)
        
        @classmethod
        def Dump(cls, *args):
            return super().Dump(hash, *args)
    
    StructById[hash] = struct_cl
    StructByName[name] = struct_cl
    return struct_cl
        
Struct('process_resPQ', 0x05162463, nonce=Int(128), server_nonce=Int(128), pq=String, fingerprints=Vector(Long))
Struct('server_DH_params_fail', 0x79cb045d, nonce=Int(128), server_nonce=Int(128), new_nonce_hash=Int(128)) 
Struct('server_DH_params_ok', 0xd0e8075c, nonce=Int(128), server_nonce=Int(128), encrypted_answer=String) 
Struct('dh_gen_ok', 0x3bcbf734, nonce=Int(128), server_nonce=Int(128), new_nonce_hash1=Int(128))
Struct('dh_gen_retry', 0x46dc1fb9, nonce=Int(128), server_nonce=Int(128), new_nonce_hash2=Int(128))
Struct('dh_gen_fail', 0xa69dae02, nonce=Int(128), server_nonce=Int(128), new_nonce_hash3=Int(128))
Struct('req_pq', 0x60469778, nonce=Int(128))
Struct('p_q_inner_data', 0x83c95aec, pq=String, p=String, q=String, nonce=Int(128), server_nonce=Int(128), new_nonce=Int(256))
Struct('req_DH_params', 0xd712e4be, nonce=Int(128), server_nonce=Int(128), p=String, q=String, public_key_fingerprint=Long, encrypted_data=String)
Struct('rsa_public_key', 0x7a19cb76, n=String, e=String)
Struct('set_client_DH_params', 0xf5045f1f, nonce=Int(128), server_nonce=Int(128), encrypted_data=String)
Struct('client_DH_inner_data', 0x6643b654, nonce=Int(128), server_nonce=Int(128), retry_id=Long, g_b=String)

if __name__ == "__main__":
    class test_cl(Struct("test_struct", 0x12345678, x=Int())):
        @classmethod
        def Dump(cls, x):
            return super().Dump(x)

    t = StructByName['test_struct']()
    data = t.Dump(123)
    print(hex(int.from_bytes(data, 'big'))[2:].upper())
    x, ln = test_cl.Parse(data)
    print(x.Name(), x.__dict__, x.x)
    

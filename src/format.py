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

class Bytes(Type):
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

class String(Bytes):
    @classmethod
    def Parse(cls, data, offset=0):
        result, ln = super().Parse(data, offset)
        return (result.decode(), ln)

    @classmethod
    def Dump(cls, value):
        return super().Dump(value.encode())

class BigInt(Bytes):
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

class Namespace:
    def __init__(self):
        self.members = {}
    def __getattr__(self, name):
        if name not in self.members:
            raise AttributeError('Member "{}" was not found'.format(name))
        return self.members[name]

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

    class struct:
        def __init__(self, name, hash, types, values):
            self._name = name
            self._hash = hash
            self._types = types
            for tipe, value in zip(types, values):
                setattr(self, tipe.name, value)
        
        def Name(self):
            return self._name
        
        def Hash(self):
            return self._hash
        
        def __str__(self):
            return '{}({})'.format(self._name, ', '.join('{}={}'.format(tipe.name, getattr(self, tipe.name)) for tipe in self._types))

        def __repr__(self):
            return self.__str__()

    @classmethod
    def Register(box_cls, name, hash, *types):
        class struct_cl(Tuple(*types)):
            @classmethod
            def Name(cls):
                return name
            
            @classmethod
            def Hash(cls):
                return hash
            
            @classmethod
            def Create(cls, *values):
                return box_cls.struct(name, hash, types, values)
            
            @classmethod
            def Parse(cls, data, offset=0):
                data, ln = cls.__bases__[0].Parse(data, offset)
                return (cls.Create(*data), ln)
            
            @classmethod
            def Dump(cls, value):
                return cls.__bases__[0].Dump(tuple(getattr(value, tipe.name) for tipe in types))

        cls = box_cls
        while cls != Type:
            cls[hash] = struct_cl
            cls[name] = struct_cl
            cls = cls.__bases__[0]

        namespace = globals()
        names = name.split('.')
        for name_part in names[:-1]:
            if name_part not in namespace:
                namespace[name_part] = Namespace()
            namespace = namespace[name_part].members
        namespace[names[-1]] = struct_cl

class MesuredBox(Box, metaclass=BoxType):
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
    @classmethod
    def Parse(cls, data, offset=0):
        data, ln = super().Parse(data, offset)
        return (data.Name() != 'boolFalse', ln)
    
    @classmethod
    def Dump(cls, value):
        if value:
            return super().Dump(boolTrue.Create())
        else:
            return super().Dump(boolFalse.Create())

class Wrapper(Box, metaclass=BoxType):
    class struct(Box.struct):
        def Name(self):
            return self.query.Name()

for type_name in ('User', 'UserProfilePhoto', 'UserStatus', 'FileLocation'):
    class custom_box(Box, metaclass=BoxType):
        pass
    globals()[type_name] = custom_box

Box.Register('resPQ', 0x05162463, Int128('nonce'), Int128('server_nonce'), BigInt('pq'), VectorBox(Long)('server_public_key_fingerprints'))
Box.Register('server_DH_params_fail', 0x79cb045d, Int128('nonce'), Int128('server_nonce'), Int128('new_nonce_hash'))
Box.Register('server_DH_params_ok', 0xd0e8075c, Int128('nonce'), Int128('server_nonce'), Bytes('encrypted_answer'))
Box.Register('server_DH_inner_data', 0xb5890dba, Int128('nonce'), Int128('server_nonce'), Int('g'), BigInt('dh_prime'), BigInt('g_a'), Int('server_time'))
Box.Register('dh_gen_ok', 0x3bcbf734, Int128('nonce'), Int128('server_nonce'), Int128('new_nonce_hash1'))
Box.Register('dh_gen_retry', 0x46dc1fb9, Int128('nonce'), Int128('server_nonce'), Int128('new_nonce_hash2'))
Box.Register('dh_gen_fail', 0xa69dae02, Int128('nonce'), Int128('server_nonce'), Int128('new_nonce_hash3'))
Box.Register('req_pq', 0x60469778, Int128('nonce'))
Box.Register('p_q_inner_data', 0x83c95aec, BigInt('pq'), BigInt('p'), BigInt('q'), Int128('nonce'), Int128('server_nonce'), Int256('new_nonce'))
Box.Register('req_DH_params', 0xd712e4be, Int128('nonce'), Int128('server_nonce'), BigInt('p'), BigInt('q'), Long('public_key_fingerprint'), Bytes('encrypted_data'))
Box.Register('rsa_public_key', 0x7a19cb76, BigInt('n'), BigInt('e'))
Box.Register('set_client_DH_params', 0xf5045f1f, Int128('nonce'), Int128('server_nonce'), Bytes('encrypted_data'))
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
Wrapper.Register('invokeWithLayer', 0xda9b0d0d, Int('layer'), Box('query'))
Wrapper.Register('initConnection', 0x69796de9, Int('api_id'), String('device_model'), String('system_version'), String('app_version'), String('lang_code'), Box('query'))
Box.Register('auth_sentCode', 0x2215bcbd, Bool('phone_registered'), String('phone_code_hash')) # 11
Box.Register('auth_sentCode', 0xefed51d9, Bool('phone_registered'), String('phone_code_hash'), Int('send_call_timeout'), Bool('is_password')) # 23
Box.Register('auth_sentAppCode', 0xe325edcf, Bool('phone_registered'), String('phone_code_hash'), Int('send_call_timeout'), Bool('is_password'))
Box.Register('auth_sendCode', 0x768d5f4d, String('phone_number'), Int('sms_type'), Int('api_id'), String('api_hash'), String('lang_code'))
FileLocation.Register('fileLocationUnavailable', 0x7c596b46, Long('volume_id'), Int('local_id'), Long('secret'))
FileLocation.Register('fileLocation', 0x53d69076, Int('dc_id'), Long('volume_id'), Int('local_id'), Long('secret'))
UserProfilePhoto.Register('userProfilePhotoEmpty', 0x4f11bae1)
UserProfilePhoto.Register('userProfilePhoto', 0xd559d8c8, Long('photo_id'), FileLocation('photo_small'), FileLocation('photo_big'))
UserStatus.Register('userStatusEmpty', 0x9d05049)
UserStatus.Register('userStatusOnline', 0xedb93949, Int('expires'))
UserStatus.Register('userStatusOffline', 0x8c703f, Int('was_online'))
UserStatus.Register('userStatusRecently', 0xe26f42f1)
UserStatus.Register('userStatusLastWeek', 0x7bf09fc)
UserStatus.Register('userStatusLastMonth', 0x77ebc742)
User.Register('userEmpty', 0x200250ba, Int('id'))
User.Register('userSelf', 0x720535ec, Int('id'), String('first_name'), String('last_name'), String('phone'), UserProfilePhoto('photo'), UserStatus('status'), Bool('inactive'))
User.Register('userSelf', 0x7007b451, Int('id'), String('first_name'), String('last_name'), String('username'), String('phone'), UserProfilePhoto('photo'), UserStatus('status'), Bool('inactive'))
User.Register('userContact', 0xcab35e18, Int('id'), String('first_name'), String('last_name'), String('username'), Long('access_hash'), String('phone'), UserProfilePhoto('photo'), UserStatus('status'))
User.Register('userRequest', 0xd9ccc4ef, Int('id'), String('first_name'), String('last_name'), String('username'), Long('access_hash'), String('phone'), UserProfilePhoto('photo'), UserStatus('status'))
User.Register('userForeign', 0x75cf7a8, Int('id'), String('first_name'), String('last_name'), String('username'), Long('access_hash'), UserProfilePhoto('photo'), UserStatus('status'))
User.Register('userDeleted', 0xd6016d7a, Int('id'), String('first_name'), String('last_name'), String('username'))
Box.Register('auth_authorization', 0xf6b673a4, Int('expires'), User('user'))
Box.Register('auth_signIn', 0xbcd51581, String('phone_number'), String('phone_code_hash'), String('phone_code'))
Box.Register('auth_signUp', 0x1b067634, String('phone_number'), String('phone_code_hash'), String('phone_code'), String('first_name'), String('last_name'))
Box.Register('account_updateStatus', 0x6628562c, Bool('offline'))
Box.Register('auth_exportedAuthorization', 0xdf969c2d, Int('id'), Bytes('bytes'))
Box.Register('auth_importAuthorization', 0xe3ef9613, Int('id'), Bytes('bytes'))
Box.Register('auth_exportAuthorization', 0xe5bfffcd, Int('dc_id'))

if __name__ == "__main__":
    Register("test_struct", 0x12345678, Int, Int)

    test_cl = StructByName['test_struct']
    t = test_cl()
    data = Box.Dump(t.Create(123, 456))
    print(hex(int.from_bytes(data, 'big'))[2:].upper())
    x, ln = Box.Parse(data)
    print(x)
    

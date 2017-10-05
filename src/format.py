# -*- coding: utf8 -*-
import logging
import struct
import gzip

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
        def Name(cls):
            return 'vector'
        
        @classmethod
        def Hash(cls):
            return 0x1cb5c415
        
        @classmethod
        def Parse(cls, data, offset=0):
            reslen = 0
            _, ln = Int.Parse(data, offset+reslen) # hash
            reslen += ln
            result, ln = super().Parse(data, offset+reslen)
            reslen += ln
            return (result, reslen)
        
        @classmethod
        def Dump(cls, value):
            result = Int.Dump(cls.Hash())
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

class GZipPacked(Type):
    @classmethod
    def Name(cls):
        return 'gzip_packed' 

    @classmethod
    def Hash(cls):
        return 0x3072cfa1

    @classmethod
    def Parse(cls, data, offset=0):
        result, ln = Bytes.Parse(data, offset)
        result, _ = Box.Parse(gzip.decompress(result), 0)
        return (result, ln)

    @classmethod
    def Dump(cls, value):
        return Bytes.Dump(gzip.compress(Box.Dump(value)))

# MTProto 

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

# service messages

Box.Register('rpc_result', 0xf35c6d01, Long('req_msg_id'), Box('result'))
Box.Register('rpc_error', 0x2144ca19, Int('error_code'), String('error_message'))
Box.Register('rpc_drop_answer', 0x58e4a740, Long('req_msg_id'))
Box.Register('rpc_answer_unknown', 0x5e2ad36e)
Box.Register('rpc_answer_dropped_running', 0xcd78e586)
Box.Register('rpc_answer_dropped', 0xa43ad8b7, Long('msg_id'), Int('seq_no'), Int('bytes'))
Box.Register('get_future_salts', 0xb921bd04, Int('num'))
Box.Register('future_salt', 0x0949d9dc, Int('valid_since'), Int('valid_until'), Long('salt'))
Box.Register('future_salts', 0xae500895, Long('req_msg_id'), Int('now'), Vector(future_salt)('salts'))
Box.Register('ping', 0x7abe77ec, Long('ping_id'))
Box.Register('pong', 0x347773c5, Long('msg_id'), Long('ping_id'))
Box.Register('ping_delay_disconnect', 0xf3427b8c, Long('ping_id'), Int('disconnect_delay'))
Box.Register('destroy_session', 0xe7512126, Long('session_id'))
Box.Register('destroy_session_ok', 0xe22045fc, Long('session_id'))
Box.Register('destroy_session_none', 0x62d350c9, Long('session_id'))
Box.Register('new_session_created', 0x9ec20908, Long('first_msg_id'), Long('unique_id'), Long('server_salt'))
Box.Register('message', 0x5bb8e511, Long('msg_id'), Int('seqno'), MesuredBox('body'))
Box.Register('msg_container', 0x73f1f8dc, Vector(message)('messages'))
Box.Register('msg_copy', 0xe06046b2, Box('orig_message'))

Box[GZipPacked.Hash()] = GZipPacked
Box[GZipPacked.Name()] = GZipPacked 

# service messages about messages

Box.Register('msgs_ack', 0x62d6b459, VectorBox(Long)('msg_ids'))
Box.Register('bad_msg_notification', 0xa7eff811, Long('bad_msg_id'), Int('bad_msg_seqno'), Int('error_code'))
Box.Register('bad_server_salt', 0xedab447b, Long('bad_msg_id'), Int('bad_msg_seqno'), Int('error_code'), Long('new_server_salt'))
Box.Register('msgs_state_req', 0xda69fb52, VectorBox(Long)('msg_ids'))
Box.Register('msgs_state_info', 0x04deb57d, Long('req_msg_id'), String('info'))
Box.Register('msgs_all_info', 0x8cc0d131, VectorBox(Long)('msg_ids'), String('info'))
Box.Register('msg_detailed_info', 0x276d3ec6, Long('msg_id'), Long('answer_msg_id'), Int('bytes'), Int('status'))
Box.Register('msg_new_detailed_info', 0x809db6df, Long('answer_msg_id'), Int('bytes'), Int('status'))
Box.Register('msg_resend_req', 0x7d861a08, VectorBox(Long)('msg_ids'))
Box.Register('msg_resend_ans_req', 0x8610baeb, VectorBox(Long)('msg_ids'))

# api structs

for type_name in (
        'AccountDaysTTL',
        'Audio',
        'Chat',
        'ChatParticipant',
        'ChatParticipants',
        'ChatPhoto',
        'ChatFull',
        'Contact',
        'ContactBlocked',
        'ContactFound',
        'ContactStatus',
        'DcOption',
        'Dialog',
        'DisabledFeature',
        'Document',
        'DocumentAttribute',
        'EncryptedChat',
        'EncryptedFile',
        'EncryptedMessage',
        'FileLocation',
        'GeoPoint',
        'ImportedContact',
        'InputAppEvent',
        'InputAudio',
        'InputChatPhoto',
        'InputContact',
        'InputDocument',
        'InputEncryptedChat',
        'InputEncryptedFile',
        'InputFile',
        'InputFileLocation',
        'InputGeoPoint',
        'InputMedia',
        'InputNotifyPeer',
        'InputPeer',
        'InputPeerNotifySettings',
        'InputPhoto',
        'InputPhotoCrop',
        'InputPrivacyKey',
        'InputPrivacyRule',
        'InputUser',
        'InputVideo',
        'Message',
        'MessageAction',
        'MessageMedia',
        'MessagesFilter',
        'NotifyPeer',
        'Peer',
        'PeerNotifySettings',
        'Photo',
        'PhotoSize',
        'PrivacyKey',
        'PrivacyRule',
        'ReportReason',
        'SendMessageAction',
        'StickerPack',
        'Update',
        'User',
        'UserProfilePhoto',
        'UserStatus',
        'Video',
        'WallPaper',
        'contacts_ForeignLink',
        'contacts_Link',
        'contacts_MyLink',
        'storage_FileType',
        'updates_State'):
    class custom_box(Box, metaclass=BoxType):
        pass
    globals()[type_name] = custom_box


Box[VectorBox(Box).Hash()] = VectorBox(Box)
Box[VectorBox(Box).Name()] = VectorBox(Box) 

Bool.Register('boolFalse', 0xbc799737)
Bool.Register('boolTrue', 0x997275b5)
Box.Register('error', 0xc4b9f9bb, Int('code'), String('text'))
Box.Register('null', 0x56730bcc)

InputPeer.Register('inputPeerEmpty', 0x7f3b18ea)
InputPeer.Register('inputPeerSelf', 0x7da07ec9)
InputPeer.Register('inputPeerContact', 0x1023dbe8, Int('user_id'))
InputPeer.Register('inputPeerForeign', 0x9b447325, Int('user_id'), Long('access_hash'))
InputPeer.Register('inputPeerChat', 0x179be863, Int('chat_id'))

InputUser.Register('inputUserEmpty', 0xb98886cf)
InputUser.Register('inputUserSelf', 0xf7c1b13f)
InputUser.Register('inputUserContact', 0x86e94f65, Int('user_id'))
InputUser.Register('inputUserForeign', 0x655e74ff, Int('user_id'), Long('access_hash'))

InputContact.Register('inputPhoneContact', 0xf392b7f4, Long('client_id'), String('phone'), String('first_name'), String('last_name'))

InputFile.Register('inputFile', 0xf52ff27f, Long('id'), Int('parts'), String('name'), String('md5_checksum'))
InputFile.Register('inputFileBig', 0xfa4f0bb5, Long('id'), Int('parts'), String('name'))

InputMedia.Register('inputMediaEmpty', 0x9664f57f)
InputMedia.Register('inputMediaUploadedPhoto', 0x2dc53a7d, InputFile('file'))
InputMedia.Register('inputMediaPhoto', 0x8f2ab2ec, InputPhoto('id'))
InputMedia.Register('inputMediaGeoPoint', 0xf9c44144, InputGeoPoint('geo_point'))
InputMedia.Register('inputMediaContact', 0xa6e45987, String('phone_number'), String('first_name'), String('last_name'))
InputMedia.Register('inputMediaUploadedVideo', 0x133ad6f6, InputFile('file'), Int('duration'), Int('w'), Int('h'), String('mime_type'))
InputMedia.Register('inputMediaUploadedThumbVideo', 0x9912dabf, InputFile('file'), InputFile('thumb'), Int('duration'), Int('w'), Int('h'), String('mime_type'))
InputMedia.Register('inputMediaVideo', 0x7f023ae6, InputVideo('id'))
InputMedia.Register('inputMediaUploadedAudio', 0x4e498cab, InputFile('file'), Int('duration'), String('mime_type'))
InputMedia.Register('inputMediaAudio', 0x89938781, InputAudio('id'))
InputMedia.Register('inputMediaUploadedDocument', 0xffe76b78, InputFile('file'), String('mime_type'), VectorBox(DocumentAttribute)('attributes'))
InputMedia.Register('inputMediaUploadedThumbDocument', 0x41481486, InputFile('file'), InputFile('thumb'), String('mime_type'), VectorBox(DocumentAttribute)('attributes'))
InputMedia.Register('inputMediaDocument', 0xd184e841, InputDocument('id'))

InputChatPhoto.Register('inputChatPhotoEmpty', 0x1ca48f57)
InputChatPhoto.Register('inputChatUploadedPhoto', 0x94254732, InputFile('file'), InputPhotoCrop('crop'))
InputChatPhoto.Register('inputChatPhoto', 0xb2e1bf08, InputPhoto('id'), InputPhotoCrop('crop'))

InputGeoPoint.Register('inputGeoPointEmpty', 0xe4c123d6)
InputGeoPoint.Register('inputGeoPoint', 0xf3b7acc9, Double('lat'), Double('Long'))

InputPhoto.Register('inputPhotoEmpty', 0x1cd7bf0d)
InputPhoto.Register('inputPhoto', 0xfb95c6c4, Long('id'), Long('access_hash'))

InputVideo.Register('inputVideoEmpty', 0x5508ec75)
InputVideo.Register('inputVideo', 0xee579652, Long('id'), Long('access_hash'))

InputFileLocation.Register('inputFileLocation', 0x14637196, Long('volume_id'), Int('local_id'), Long('secret'))
InputFileLocation.Register('inputVideoFileLocation', 0x3d0364ec, Long('id'), Long('access_hash'))
InputFileLocation.Register('inputEncryptedFileLocation', 0xf5235d55, Long('id'), Long('access_hash'))
InputFileLocation.Register('inputAudioFileLocation', 0x74dc404d, Long('id'), Long('access_hash'))
InputFileLocation.Register('inputDocumentFileLocation', 0x4e45abe9, Long('id'), Long('access_hash'))

InputPhotoCrop.Register('inputPhotoCropAuto', 0xade6b004)
InputPhotoCrop.Register('inputPhotoCrop', 0xd9915325, Double('crop_left'), Double('crop_top'), Double('crop_width'))

InputAppEvent.Register('inputAppEvent', 0x770656a8, Double('time'), String('type'), Long('peer'), String('data'))

Peer.Register('peerUser', 0x9db1bc6d, Int('user_id'))
Peer.Register('peerChat', 0xbad0e5bb, Int('chat_id'))

storage_FileType.Register('storage_fileUnknown', 0xaa963b05)
storage_FileType.Register('storage_fileJpeg', 0x7efe0e)
storage_FileType.Register('storage_fileGif', 0xcae1aadf)
storage_FileType.Register('storage_filePng', 0xa4f63c0)
storage_FileType.Register('storage_filePdf', 0xae1e508d)
storage_FileType.Register('storage_fileMp3', 0x528a0677)
storage_FileType.Register('storage_fileMov', 0x4b09ebbc)
storage_FileType.Register('storage_filePartial', 0x40bc6f52)
storage_FileType.Register('storage_fileMp4', 0xb3cea0e4)
storage_FileType.Register('storage_fileWebp', 0x1081464c)

FileLocation.Register('fileLocationUnavailable', 0x7c596b46, Long('volume_id'), Int('local_id'), Long('secret'))
FileLocation.Register('fileLocation', 0x53d69076, Int('dc_id'), Long('volume_id'), Int('local_id'), Long('secret'))

User.Register('userEmpty', 0x200250ba, Int('id'))
User.Register('userSelf', 0x720535ec, Int('id'), String('first_name'), String('last_name'), String('phone'), UserProfilePhoto('photo'), UserStatus('status'), Bool('inactive'))
User.Register('userSelf', 0x7007b451, Int('id'), String('first_name'), String('last_name'), String('username'), String('phone'), UserProfilePhoto('photo'), UserStatus('status'), Bool('inactive'))
User.Register('userContact', 0xcab35e18, Int('id'), String('first_name'), String('last_name'), String('username'), Long('access_hash'), String('phone'), UserProfilePhoto('photo'), UserStatus('status'))
User.Register('userRequest', 0xd9ccc4ef, Int('id'), String('first_name'), String('last_name'), String('username'), Long('access_hash'), String('phone'), UserProfilePhoto('photo'), UserStatus('status'))
User.Register('userForeign', 0x75cf7a8, Int('id'), String('first_name'), String('last_name'), String('username'), Long('access_hash'), UserProfilePhoto('photo'), UserStatus('status'))
User.Register('userDeleted', 0xd6016d7a, Int('id'), String('first_name'), String('last_name'), String('username'))

UserProfilePhoto.Register('userProfilePhotoEmpty', 0x4f11bae1)
UserProfilePhoto.Register('userProfilePhoto', 0xd559d8c8, Long('photo_id'), FileLocation('photo_small'), FileLocation('photo_big'))

UserStatus.Register('userStatusEmpty', 0x9d05049)
UserStatus.Register('userStatusOnline', 0xedb93949, Int('expires'))
UserStatus.Register('userStatusOffline', 0x8c703f, Int('was_online'))
UserStatus.Register('userStatusRecently', 0xe26f42f1)
UserStatus.Register('userStatusLastWeek', 0x7bf09fc)
UserStatus.Register('userStatusLastMonth', 0x77ebc742)

Chat.Register('chatEmpty', 0x9ba2d800, Int('id'))
Chat.Register('chat', 0x6e9c9bc7, Int('id'), String('title'), ChatPhoto('photo'), Int('participants_count'), Int('date'), Bool('left'), Int('version'))
Chat.Register('chatForbidden', 0xfb0ccc41, Int('id'), String('title'), Int('date'))

ChatFull.Register('chatFull', 0x630e61be, Int('id'), ChatParticipants('participants'), Photo('chat_photo'), PeerNotifySettings('notify_settings'))

ChatParticipant.Register('chatParticipant', 0xc8d7493e, Int('user_id'), Int('inviter_id'), Int('date'))

ChatParticipants.Register('chatParticipantsForbidden', 0xfd2bb8a, Int('chat_id'))
ChatParticipants.Register('chatParticipants', 0x7841b415, Int('chat_id'), Int('admin_id'), VectorBox(ChatParticipant)('participants'), Int('version'))

ChatPhoto.Register('chatPhotoEmpty', 0x37c1011c)
ChatPhoto.Register('chatPhoto', 0x6153276a, FileLocation('photo_small'), FileLocation('photo_big'))

Message.Register('messageEmpty', 0x83e5de54, Int('id'))
Message.Register('messageOrdinar', 0x567699b3, Int('flags'), Int('id'), Int('from_id'), Peer('to_id'), Int('date'), String('message'), MessageMedia('media'))
Message.Register('messageForwarded', 0xa367e716, Int('flags'), Int('id'), Int('fwd_from_id'), Int('fwd_date'), Int('from_id'), Peer('to_id'), Int('date'), String('message'), MessageMedia('media'))
Message.Register('messageService', 0x1d86f70e, Int('flags'), Int('id'), Int('from_id'), Peer('to_id'), Int('date'), MessageAction('action'))

MessageMedia.Register('messageMediaEmpty', 0x3ded6320)
MessageMedia.Register('messageMediaPhoto', 0xc8c45a2a, Photo('photo'))
MessageMedia.Register('messageMediaVideo', 0xa2d24290, Video('video'))
MessageMedia.Register('messageMediaGeo', 0x56e0d474, GeoPoint('geo'))
MessageMedia.Register('messageMediaContact', 0x5e7d2f39, String('phone_number'), String('first_name'), String('last_name'), Int('user_id'))
MessageMedia.Register('messageMediaDocument', 0x2fda2204, Document('document'))
MessageMedia.Register('messageMediaAudio', 0xc6b68300, Audio('audio'))

MessageAction.Register('messageActionEmpty', 0xb6aef7b0)
MessageAction.Register('messageActionChatCreate', 0xa6638b9a, String('title'), VectorBox(Int)('users'))
MessageAction.Register('messageActionChatEditTitle', 0xb5a1ce5a, String('title'))
MessageAction.Register('messageActionChatEditPhoto', 0x7fcb13a8, Photo('photo'))
MessageAction.Register('messageActionChatDeletePhoto', 0x95e3fbef)
MessageAction.Register('messageActionChatAddUser', 0x5e3cfc4b, Int('user_id'))
MessageAction.Register('messageActionChatDeleteUser', 0xb2ae9b0c, Int('user_id'))

Dialog.Register('dialog', 0xab3a99ac, Peer('peer'), Int('top_message'), Int('unread_count'), PeerNotifySettings('notify_settings'))

Photo.Register('photoEmpty', 0x2331b22d, Long('id'))
Photo.Register('photo', 0x22b56751, Long('id'), Long('access_hash'), Int('user_id'), Int('date'), String('caption'), GeoPoint('geo'), VectorBox(PhotoSize)('sizes'))

PhotoSize.Register('photoSizeEmpty', 0xe17e23c, String('type'))
PhotoSize.Register('photoSize', 0x77bfb61b, String('type'), FileLocation('location'), Int('w'), Int('h'), Int('size'))
PhotoSize.Register('photoCachedSize', 0xe9a734fa, String('type'), FileLocation('location'), Int('w'), Int('h'), Bytes('bytes'))

Video.Register('videoEmpty', 0xc10658a8, Long('id'))
Video.Register('video', 0x388fa391, Long('id'), Long('access_hash'), Int('user_id'), Int('date'), String('caption'), Int('duration'), String('mime_type'), Int('size'), PhotoSize('thumb'), Int('dc_id'), Int('w'), Int('h'))

GeoPoint.Register('geoPointEmpty', 0x1117dd5f)
GeoPoint.Register('geoPoint', 0x2049d70c, Double('Long'), Double('lat'))

Box.Register('auth_checkedPhone', 0xe300cc3b, Bool('phone_registered'), Bool('phone_invited'))
Box.Register('auth_sentCode', 0x2215bcbd, Bool('phone_registered'), String('phone_code_hash')) # 11
Box.Register('auth_sentCode', 0xefed51d9, Bool('phone_registered'), String('phone_code_hash'), Int('send_call_timeout'), Bool('is_password'))
Box.Register('auth_sentAppCode', 0xe325edcf, Bool('phone_registered'), String('phone_code_hash'), Int('send_call_timeout'), Bool('is_password'))
Box.Register('auth_authorization', 0xf6b673a4, Int('expires'), User('user'))
Box.Register('auth_exportedAuthorization', 0xdf969c2d, Int('id'), Bytes('bytes'))

InputNotifyPeer.Register('inputNotifyPeer', 0xb8bc5b0c, InputPeer('peer'))
InputNotifyPeer.Register('inputNotifyUsers', 0x193b4417)
InputNotifyPeer.Register('inputNotifyChats', 0x4a95e84e)
InputNotifyPeer.Register('inputNotifyAll', 0xa429b886)

Box.Register('inputPeerNotifyEventsEmpty', 0xf03064d8)
Box.Register('inputPeerNotifyEventsAll', 0xe86a2c74)

InputPeerNotifySettings.Register('inputPeerNotifySettings', 0x46a2ce98, Int('mute_until'), String('sound'), Bool('show_previews'), Int('events_mask'))

Box.Register('peerNotifyEventsEmpty', 0xadd53cb3)
Box.Register('peerNotifyEventsAll', 0x6d1ded88)

PeerNotifySettings.Register('peerNotifySettingsEmpty', 0x70a68512)
PeerNotifySettings.Register('peerNotifySettings', 0x8d5e11ee, Int('mute_until'), String('sound'), Bool('show_previews'), Int('events_mask'))

WallPaper.Register('wallPaper', 0xccb03657, Int('id'), String('title'), VectorBox(PhotoSize)('sizes'), Int('color'))
WallPaper.Register('wallPaperSolid', 0x63117f24, Int('id'), String('title'), Int('bg_color'), Int('color'))

ReportReason.Register('inputReportReasonSpam', 0x58dbcab8)
ReportReason.Register('inputReportReasonViolence', 0x1e22c78d)
ReportReason.Register('inputReportReasonPornography', 0x2e59d922)
ReportReason.Register('inputReportReasonOther', 0xe1746d0a, String('text'))

Box.Register('userFull', 0x771095da, User('user'), contacts_Link('link'), Photo('profile_photo'), PeerNotifySettings('notify_settings'), Bool('blocked'), String('real_first_name'), String('real_last_name'))

Contact.Register('contact', 0xf911c994, Int('user_id'), Bool('mutual'))

ImportedContact.Register('importedContact', 0xd0028438, Int('user_id'), Long('client_id'))

ContactBlocked.Register('contactBlocked', 0x561bc879, Int('user_id'), Int('date'))

ContactStatus.Register('contactStatus', 0xd3680c61, Int('user_id'), UserStatus('status'))

contacts_ForeignLink.Register('contacts_foreignLinkUnknown', 0x133421f8)
contacts_ForeignLink.Register('contacts_foreignLinkRequested', 0xa7801f47, Bool('has_phone'))
contacts_ForeignLink.Register('contacts_foreignLinkMutual', 0x1bea8ce1)

contacts_MyLink.Register('contacts_myLinkEmpty', 0xd22a1c60)
contacts_MyLink.Register('contacts_myLinkRequested', 0x6c69efee, Bool('contact'))
contacts_MyLink.Register('contacts_myLinkContact', 0xc240ebd9)

contacts_Link.Register('contacts_link', 0xeccea3f5, contacts_MyLink('my_link'), contacts_ForeignLink('foreign_link'), User('user'))

Box.Register('contacts_contactsNotModified', 0xb74ba9d2)
Box.Register('contacts_contacts', 0x6f8b8cb2, VectorBox(Contact)('contacts'), VectorBox(User)('users'))

Box.Register('contacts_importedContacts', 0xad524315, VectorBox(ImportedContact)('imported'), VectorBox(Long)('retry_contacts'), VectorBox(User)('users'))

Box.Register('contacts_blocked', 0x1c138d15, VectorBox(ContactBlocked)('blocked'), VectorBox(User)('users'))
Box.Register('contacts_blockedSlice', 0x900802a1, Int('count'), VectorBox(ContactBlocked)('blocked'), VectorBox(User)('users'))

Box.Register('messages_dialogs', 0x15ba6c40, VectorBox(Dialog)('dialogs'), VectorBox(Message)('messages'), VectorBox(Chat)('chats'), VectorBox(User)('users'))
Box.Register('messages_dialogsSlice', 0x71e094f3, Int('count'), VectorBox(Dialog)('dialogs'), VectorBox(Message)('messages'), VectorBox(Chat)('chats'), VectorBox(User)('users'))

Box.Register('messages_messages', 0x8c718e87, VectorBox(Message)('messages'), VectorBox(Chat)('chats'), VectorBox(User)('users'))
Box.Register('messages_messagesSlice', 0xb446ae3, Int('count'), VectorBox(Message)('messages'), VectorBox(Chat)('chats'), VectorBox(User)('users'))

Box.Register('messages_statedMessages', 0x969478bb, VectorBox(Message)('messages'), VectorBox(Chat)('chats'), VectorBox(User)('users'), Int('pts'), Int('seq'))
Box.Register('messages_statedMessagesLinks', 0x3e74f5c6, VectorBox(Message)('messages'), VectorBox(Chat)('chats'), VectorBox(User)('users'), VectorBox(contacts_Link)('links'), Int('pts'), Int('seq'))

Box.Register('messages_statedMessage', 0xd07ae726, Message('message'), VectorBox(Chat)('chats'), VectorBox(User)('users'), Int('pts'), Int('seq'))
Box.Register('messages_statedMessageLink', 0xa9af2881, Message('message'), VectorBox(Chat)('chats'), VectorBox(User)('users'), VectorBox(contacts_Link)('links'), Int('pts'), Int('seq'))

Box.Register('messages_sentMessage', 0xd1f4d35c, Int('id'), Int('date'), Int('pts'), Int('seq'))
Box.Register('messages_sentMessageLink', 0xe9db4a3f, Int('id'), Int('date'), Int('pts'), Int('seq'), VectorBox(contacts_Link)('links'))

Box.Register('messages_chats', 0x8150cbd8, VectorBox(Chat)('chats'), VectorBox(User)('users'))

Box.Register('messages_chatFull', 0xe5d7d19c, ChatFull('full_chat'), VectorBox(Chat)('chats'), VectorBox(User)('users'))

Box.Register('messages_affectedHistory', 0xb7de36f2, Int('pts'), Int('seq'), Int('offset'))

MessagesFilter.Register('inputMessagesFilterEmpty', 0x57e2f66c)
MessagesFilter.Register('inputMessagesFilterPhotos', 0x9609a51c)
MessagesFilter.Register('inputMessagesFilterVideo', 0x9fc00e65)
MessagesFilter.Register('inputMessagesFilterPhotoVideo', 0x56e9f0e4)
MessagesFilter.Register('inputMessagesFilterPhotoVideoDocuments', 0xd95e73bb)
MessagesFilter.Register('inputMessagesFilterDocument', 0x9eddf188)
MessagesFilter.Register('inputMessagesFilterAudio', 0xcfc87522)
MessagesFilter.Register('inputMessagesFilterAudioDocuments', 0x5afbf764)
MessagesFilter.Register('inputMessagesFilterUrl', 0x7ef0dd87)
MessagesFilter.Register('inputMessagesFilterGif', 0xffc86587)

Update.Register('updateNewMessage', 0x13abdb3, Message('message'), Int('pts'))
Update.Register('updateMessageID', 0x4e90bfd6, Int('id'), Long('random_id'))
Update.Register('updateReadMessages', 0xc6649e31, VectorBox(Int)('messages'), Int('pts'))
Update.Register('updateDeleteMessages', 0xa92bfe26, VectorBox(Int)('messages'), Int('pts'))
Update.Register('updateUserTyping', 0x5c486927, Int('user_id'), SendMessageAction('action'))
Update.Register('updateChatUserTyping', 0x9a65ea1f, Int('chat_id'), Int('user_id'), SendMessageAction('action'))
Update.Register('updateChatParticipants', 0x7761198, ChatParticipants('participants'))
Update.Register('updateUserStatus', 0x1bfbd823, Int('user_id'), UserStatus('status'))
Update.Register('updateUserName', 0xa7332b73, Int('user_id'), String('first_name'), String('last_name'), String('username'))
Update.Register('updateUserPhoto', 0x95313b0c, Int('user_id'), Int('date'), UserProfilePhoto('photo'), Bool('previous'))
Update.Register('updateContactRegistered', 0x2575bbb9, Int('user_id'), Int('date'))
Update.Register('updateContactLink', 0x51a48a9a, Int('user_id'), contacts_MyLink('my_link'), contacts_ForeignLink('foreign_link'))
Update.Register('updateNewAuthorization', 0x8f06529a, Long('auth_key_id'), Int('date'), String('device'), String('location'))
Update.Register('updateNewEncryptedMessage', 0x12bcbd9a, EncryptedMessage('message'), Int('qts'))
Update.Register('updateEncryptedChatTyping', 0x1710f156, Int('chat_id'))
Update.Register('updateEncryption', 0xb4a2e88d, EncryptedChat('chat'), Int('date'))
Update.Register('updateEncryptedMessagesRead', 0x38fe25b7, Int('chat_id'), Int('max_date'), Int('date'))
Update.Register('updateChatParticipantAdd', 0x3a0eeb22, Int('chat_id'), Int('user_id'), Int('inviter_id'), Int('version'))
Update.Register('updateChatParticipantDelete', 0x6e5f8c22, Int('chat_id'), Int('user_id'), Int('version'))
Update.Register('updateDcOptions', 0x8e5e9873, VectorBox(DcOption)('dc_options'))
Update.Register('updateUserBlocked', 0x80ece81a, Int('user_id'), Bool('blocked'))
Update.Register('updateNotifySettings', 0xbec268ef, NotifyPeer('peer'), PeerNotifySettings('notify_settings'))
Update.Register('updateServiceNotification', 0x382dd3e4, String('type'), String('message'), MessageMedia('media'), Bool('popup'))
Update.Register('updatePrivacy', 0xee3b272a, PrivacyKey('key'), VectorBox(PrivacyRule)('rules'))
Update.Register('updateUserPhone', 0x12b9417b, Int('user_id'), String('phone'))

updates_State.Register('updates_state', 0xa56c2a3e, Int('pts'), Int('qts'), Int('date'), Int('seq'), Int('unread_count'))

Box.Register('updates_differenceEmpty', 0x5d75a138, Int('date'), Int('seq'))
Box.Register('updates_difference', 0xf49ca0, VectorBox(Message)('new_messages'), VectorBox(EncryptedMessage)('new_encrypted_messages'), VectorBox(Update)('other_updates'), VectorBox(Chat)('chats'), VectorBox(User)('users'), updates_State('state'))
Box.Register('updates_differenceSlice', 0xa8fb1981, VectorBox(Message)('new_messages'), VectorBox(EncryptedMessage)('new_encrypted_messages'), VectorBox(Update)('other_updates'), VectorBox(Chat)('chats'), VectorBox(User)('users'), updates_State('intermediate_state'))

Box.Register('updatesTooLong', 0xe317af7e)
Box.Register('updateShortMessage', 0xd3f45784, Int('id'), Int('from_id'), String('message'), Int('pts'), Int('date'), Int('seq'))
Box.Register('updateShortChatMessage', 0x2b2fbd4e, Int('id'), Int('from_id'), Int('chat_id'), String('message'), Int('pts'), Int('date'), Int('seq'))
Box.Register('updateShort', 0x78d4dec1, Update('update'), Int('date'))
Box.Register('updatesCombined', 0x725b04c3, VectorBox(Update)('updates'), VectorBox(User)('users'), VectorBox(Chat)('chats'), Int('date'), Int('seq_start'), Int('seq'))
Box.Register('updates', 0x74ae4240, VectorBox(Update)('updates'), VectorBox(User)('users'), VectorBox(Chat)('chats'), Int('date'), Int('seq'))

Box.Register('photos_photos', 0x8dca6aa5, VectorBox(Photo)('photos'), VectorBox(User)('users'))
Box.Register('photos_photosSlice', 0x15051f54, Int('count'), VectorBox(Photo)('photos'), VectorBox(User)('users'))

Box.Register('photos_photo', 0x20212ca8, Photo('photo'), VectorBox(User)('users'))

Box.Register('upload_file', 0x96a18d5, storage_FileType('type'), Int('mtime'), Bytes('bytes'))

Box.Register('dcOption', 0x2ec2a43c, Int('id'), String('hostname'), String('ip_address'), Int('port'))

#Box.Register('config', 0x232d5905, Int('date'), Bool('test_mode'), Int('this_dc'), VectorBox(Box)('dc_options'), Int('chat_size_max'))
#Box.Register('config', 0x2e54dd74, Int('date'), Bool('test_mode'), Int('this_dc'), VectorBox(Box)('dc_options'), Int('chat_size_max'), Int('broadcast_size_max'))
Box.Register('config', 0x7dae33e0, Int('date'), Int('expires'), Bool('test_mode'), Int('this_dc'), VectorBox(Box)('dc_options'), Int('chat_big_size'), Int('chat_size_max'), Int('broadcast_size_max'), VectorBox(Box)('disabled_features'))

Box.Register('nearestDc', 0x8e1a1775, String('country'), Int('this_dc'), Int('nearest_dc'))

Box.Register('help_appUpdate', 0x8987f311, Int('id'), Bool('critical'), String('url'), String('text'))
Box.Register('help_noAppUpdate', 0xc45a6536)

Box.Register('help_inviteText', 0x18cb9f78, String('message'))

EncryptedChat.Register('encryptedChatEmpty', 0xab7ec0a0, Int('id'))
EncryptedChat.Register('encryptedChatWaiting', 0x3bf703dc, Int('id'), Long('access_hash'), Int('date'), Int('admin_id'), Int('participant_id'))
EncryptedChat.Register('encryptedChatRequested', 0xc878527e, Int('id'), Long('access_hash'), Int('date'), Int('admin_id'), Int('participant_id'), Bytes('g_a'))
EncryptedChat.Register('encryptedChat', 0xfa56ce36, Int('id'), Long('access_hash'), Int('date'), Int('admin_id'), Int('participant_id'), Bytes('g_a_or_b'), Long('key_fingerprint'))
EncryptedChat.Register('encryptedChatDiscarded', 0x13d6dd27, Int('id'))

InputEncryptedChat.Register('inputEncryptedChat', 0xf141b5e1, Int('chat_id'), Long('access_hash'))

EncryptedFile.Register('encryptedFileEmpty', 0xc21f497e)
EncryptedFile.Register('encryptedFile', 0x4a70994c, Long('id'), Long('access_hash'), Int('size'), Int('dc_id'), Int('key_fingerprint'))

InputEncryptedFile.Register('inputEncryptedFileEmpty', 0x1837c364)
InputEncryptedFile.Register('inputEncryptedFileUploaded', 0x64bd0306, Long('id'), Int('parts'), String('md5_checksum'), Int('key_fingerprint'))
InputEncryptedFile.Register('inputEncryptedFile', 0x5a17b5e5, Long('id'), Long('access_hash'))
InputEncryptedFile.Register('inputEncryptedFileBigUploaded', 0x2dc173c8, Long('id'), Int('parts'), Int('key_fingerprint'))

EncryptedMessage.Register('encryptedMessage', 0xed18c118, Long('random_id'), Int('chat_id'), Int('date'), Bytes('bytes'), EncryptedFile('file'))
EncryptedMessage.Register('encryptedMessageService', 0x23734b06, Long('random_id'), Int('chat_id'), Int('date'), Bytes('bytes'))

Box.Register('messages_dhConfigNotModified', 0xc0e24635, Bytes('random'))
Box.Register('messages_dhConfig', 0x2c221edd, Int('g'), Bytes('p'), Int('version'), Bytes('random'))

Box.Register('messages_sentEncryptedMessage', 0x560f8935, Int('date'))
Box.Register('messages_sentEncryptedFile', 0x9493ff32, Int('date'), EncryptedFile('file'))

InputAudio.Register('inputAudioEmpty', 0xd95adc84)
InputAudio.Register('inputAudio', 0x77d440ff, Long('id'), Long('access_hash'))

InputDocument.Register('inputDocumentEmpty', 0x72f0eaae)
InputDocument.Register('inputDocument', 0x18798952, Long('id'), Long('access_hash'))

Audio.Register('audioEmpty', 0x586988d8, Long('id'))
Audio.Register('audio', 0xc7ac6496, Long('id'), Long('access_hash'), Int('user_id'), Int('date'), Int('duration'), String('mime_type'), Int('size'), Int('dc_id'))

Document.Register('documentEmpty', 0x36f8c871, Long('id'))
Document.Register('document', 0xf9a39f4f, Long('id'), Long('access_hash'), Int('date'), String('mime_type'), Int('size'), PhotoSize('thumb'), Int('dc_id'), VectorBox(DocumentAttribute)('attributes'))

Box.Register('help_support', 0x17c6b5f6, String('phone_number'), User('user'))

NotifyPeer.Register('notifyPeer', 0x9fd40bd8, Peer('peer'))
NotifyPeer.Register('notifyUsers', 0xb4c83b4c)
NotifyPeer.Register('notifyChats', 0xc007cec3)
NotifyPeer.Register('notifyAll', 0x74d07c60)

SendMessageAction.Register('sendMessageTypingAction', 0x16bf744e)
SendMessageAction.Register('sendMessageCancelAction', 0xfd5ec8f5)
SendMessageAction.Register('sendMessageRecordVideoAction', 0xa187d66f)
SendMessageAction.Register('sendMessageUploadVideoAction', 0x92042ff7)
SendMessageAction.Register('sendMessageRecordAudioAction', 0xd52f73f7)
SendMessageAction.Register('sendMessageUploadAudioAction', 0xe6ac8a6f)
SendMessageAction.Register('sendMessageUploadPhotoAction', 0x990a3c1a)
SendMessageAction.Register('sendMessageUploadDocumentAction', 0x8faee98e)
SendMessageAction.Register('sendMessageGeoLocationAction', 0x176f8ba1)
SendMessageAction.Register('sendMessageChooseContactAction', 0x628cbc6f)

ContactFound.Register('contactFound', 0xea879f95, Int('user_id'))

Box.Register('contacts_found', 0x566000e, VectorBox(ContactFound)('results'), VectorBox(User)('users'))

InputPrivacyKey.Register('inputPrivacyKeyStatusTimestamp', 0x4f96cb18)

PrivacyKey.Register('privacyKeyStatusTimestamp', 0xbc2eab30)

InputPrivacyRule.Register('inputPrivacyValueAllowContacts', 0xd09e07b)
InputPrivacyRule.Register('inputPrivacyValueAllowAll', 0x184b35ce)
InputPrivacyRule.Register('inputPrivacyValueAllowUsers', 0x131cc67f, VectorBox(InputUser)('users'))
InputPrivacyRule.Register('inputPrivacyValueDisallowContacts', 0xba52007)
InputPrivacyRule.Register('inputPrivacyValueDisallowAll', 0xd66b66c9)
InputPrivacyRule.Register('inputPrivacyValueDisallowUsers', 0x90110467, VectorBox(InputUser)('users'))

PrivacyRule.Register('privacyValueAllowContacts', 0xfffe1bac)
PrivacyRule.Register('privacyValueAllowAll', 0x65427b82)
PrivacyRule.Register('privacyValueAllowUsers', 0x4d5bbe0c, VectorBox(Int)('users'))
PrivacyRule.Register('privacyValueDisallowContacts', 0xf888fa1a)
PrivacyRule.Register('privacyValueDisallowAll', 0x8b73e763)
PrivacyRule.Register('privacyValueDisallowUsers', 0xc7f49b7, VectorBox(Int)('users'))

Box.Register('account_privacyRules', 0x554abb6f, VectorBox(PrivacyRule)('rules'), VectorBox(User)('users'))

AccountDaysTTL.Register('accountDaysTTL', 0xb8d0afdf, Int('days'))

Box.Register('account_sentChangePhoneCode', 0xa4f58c4c, String('phone_code_hash'), Int('send_call_timeout'))

DocumentAttribute.Register('documentAttributeImageSize', 0x6c37c15c, Int('w'), Int('h'))
DocumentAttribute.Register('documentAttributeAnimated', 0x11b58939)
DocumentAttribute.Register('documentAttributeSticker', 0xfb0a5727)
DocumentAttribute.Register('documentAttributeVideo', 0x5910cccb, Int('duration'), Int('w'), Int('h'))
DocumentAttribute.Register('documentAttributeAudio', 0x51448e5, Int('duration'))
DocumentAttribute.Register('documentAttributeFilename', 0x15590068, String('file_name'))

Box.Register('messages_stickersNotModified', 0xf1749a22)
Box.Register('messages_stickers', 0x8a8ecd32, String('hash'), VectorBox(Document)('stickers'))

StickerPack.Register('stickerPack', 0x12b299d4, String('emoticon'), VectorBox(Long)('documents'))

Box.Register('messages_allStickersNotModified', 0xe86602c3)
Box.Register('messages_allStickers', 0xdcef3102, String('hash'), VectorBox(StickerPack)('packs'), VectorBox(Document)('documents'))

DisabledFeature.Register('disabledFeature', 0xae636f24, String('feature'), String('description'))

# api functions

Wrapper.Register('invokeAfterMsg', 0xcb9f372d, Long('msg_id'), Box('query'))
Wrapper.Register('invokeAfterMsgs', 0x3dc4b4f0, VectorBox(Long)('msg_ids'), Box('query'))
Wrapper.Register('initConnection', 0x69796de9, Int('api_id'), String('device_model'), String('system_version'), String('app_version'), String('lang_code'), Box('query'))
Wrapper.Register('invokeWithLayer', 0xda9b0d0d, Int('layer'), Box('query'))

Box.Register('auth_checkPhone', 0x6fe51dfb, String('phone_number'))
Box.Register('auth_sendCode', 0x768d5f4d, String('phone_number'), Int('sms_type'), Int('api_id'), String('api_hash'), String('lang_code'))
Box.Register('auth_sendCall', 0x3c51564, String('phone_number'), String('phone_code_hash'))
Box.Register('auth_signUp', 0x1b067634, String('phone_number'), String('phone_code_hash'), String('phone_code'), String('first_name'), String('last_name'))
Box.Register('auth_signIn', 0xbcd51581, String('phone_number'), String('phone_code_hash'), String('phone_code'))
Box.Register('auth_logOut', 0x5717da40)
Box.Register('auth_resetAuthorizations', 0x9fab0d1a)
Box.Register('auth_sendInvites', 0x771c1d97, VectorBox(String)('phone_numbers'), String('message'))
Box.Register('auth_exportAuthorization', 0xe5bfffcd, Int('dc_id'))
Box.Register('auth_importAuthorization', 0xe3ef9613, Int('id'), Bytes('bytes'))
Box.Register('auth_bindTempAuthKey', 0xcdd42a05, Long('perm_auth_key_id'), Long('nonce'), Int('expires_at'), Bytes('encrypted_message'))
Box.Register('auth_sendSms', 0xda9f3e8, String('phone_number'), String('phone_code_hash'))

Box.Register('account_registerDevice', 0x446c712c, Int('token_type'), String('token'), String('device_model'), String('system_version'), String('app_version'), Bool('app_sandbox'), String('lang_code'))
Box.Register('account_unregisterDevice', 0x65c55b40, Int('token_type'), String('token'))
Box.Register('account_updateNotifySettings', 0x84be5b93, InputNotifyPeer('peer'), InputPeerNotifySettings('settings'))
Box.Register('account_getNotifySettings', 0x12b3ad31, InputNotifyPeer('peer'))
Box.Register('account_resetNotifySettings', 0xdb7e1747)
Box.Register('account_updateProfile', 0xf0888d68, String('first_name'), String('last_name'))
Box.Register('account_updateStatus', 0x6628562c, Bool('offline'))
Box.Register('account_getWallPapers', 0xc04cfac2)
Box.Register('account_reportPeer', 0xae189d5f, InputPeer('peer'), ReportReason('reason'))
Box.Register('account_checkUsername', 0x2714d86c, String('username'))
Box.Register('account_updateUsername', 0x3e0bdd7c, String('username'))
Box.Register('account_getPrivacy', 0xdadbc950, InputPrivacyKey('key'))
Box.Register('account_setPrivacy', 0xc9f81ce8, InputPrivacyKey('key'), VectorBox(InputPrivacyRule)('rules'))
Box.Register('account_deleteAccount', 0x418d4e0b, String('reason'))
Box.Register('account_getAccountTTL', 0x8fc711d)
Box.Register('account_setAccountTTL', 0x2442485e, AccountDaysTTL('ttl'))
Box.Register('account_sendChangePhoneCode', 0xa407a8f4, String('phone_number'))
Box.Register('account_changePhone', 0x70c32edb, String('phone_number'), String('phone_code_hash'), String('phone_code'))
Box.Register('account_updateDeviceLocked', 0x38df3532, Int('period'))

Box.Register('users_getUsers', 0xd91a548, VectorBox(InputUser)('id'))
Box.Register('users_getFullUser', 0xca30a5b1, InputUser('id'))

Box.Register('contacts_getStatuses', 0xc4a353ee)
Box.Register('contacts_getContacts', 0x22c6aa08, String('hash'))
Box.Register('contacts_importContacts', 0xda30b32d, VectorBox(InputContact)('contacts'), Bool('replace'))
Box.Register('contacts_deleteContact', 0x8e953744, InputUser('id'))
Box.Register('contacts_deleteContacts', 0x59ab389e, VectorBox(InputUser)('id'))
Box.Register('contacts_block', 0x332b49fc, InputUser('id'))
Box.Register('contacts_unblock', 0xe54100bd, InputUser('id'))
Box.Register('contacts_getBlocked', 0xf57c350f, Int('offset'), Int('limit'))
#Box.Register('contacts_exportCard', 0x84e53737) # returns Vector<int>
Box.Register('contacts_importCard', 0x4fe196fe, VectorBox(Int)('export_card'))
Box.Register('contacts_search', 0x11f812d8, String('q'), Int('limit'))
Box.Register('contacts_resolveUsername', 0xbf0131c, String('username'))

Box.Register('messages_getMessages', 0x4222fa74, VectorBox(Int)('id'))
Box.Register('messages_getDialogs', 0xeccf1df6, Int('offset'), Int('max_id'), Int('limit'))
Box.Register('messages_getHistory', 0x92a1df2f, InputPeer('peer'), Int('offset'), Int('max_id'), Int('limit'))
Box.Register('messages_search', 0x7e9f2ab, InputPeer('peer'), String('q'), MessagesFilter('filter'), Int('min_date'), Int('max_date'), Int('offset'), Int('max_id'), Int('limit'))
Box.Register('messages_readHistory', 0xeed884c6, InputPeer('peer'), Int('max_id'), Int('offset'), Bool('read_contents'))
Box.Register('messages_deleteHistory', 0xf4f8fb61, InputPeer('peer'), Int('offset'))
#Box.Register('messages_deleteMessages', 0x14f2dd0a, VectorBox(Int)('id')) # returns Vector<int>
#Box.Register('messages_receivedMessages', 0x28abcb68, Int('max_id')) # returns Vector<int>
Box.Register('messages_setTyping', 0xa3825e50, InputPeer('peer'), SendMessageAction('action'))
Box.Register('messages_sendMessage', 0x4cde0aab, InputPeer('peer'), String('message'), Long('random_id'))
Box.Register('messages_sendMedia', 0xa3c85d76, InputPeer('peer'), InputMedia('media'), Long('random_id'))
Box.Register('messages_forwardMessages', 0x514cd10f, InputPeer('peer'), VectorBox(Int)('id'))
Box.Register('messages_reportSpam', 0xcf1592db, InputPeer('peer'))
Box.Register('messages_hideReportSpam', 0xa8f1709b, InputPeer('peer'))
Box.Register('messages_getChats', 0x3c6aa187, VectorBox(Int)('id'))
Box.Register('messages_getFullChat', 0x3b831c66, Int('chat_id'))
Box.Register('messages_editChatTitle', 0xb4bc68b5, Int('chat_id'), String('title'))
Box.Register('messages_editChatPhoto', 0xd881821d, Int('chat_id'), InputChatPhoto('photo'))
Box.Register('messages_addChatUser', 0x2ee9ee9e, Int('chat_id'), InputUser('user_id'), Int('fwd_limit'))
Box.Register('messages_deleteChatUser', 0xc3c5cd23, Int('chat_id'), InputUser('user_id'))
Box.Register('messages_createChat', 0x419d9aee, VectorBox(InputUser)('users'), String('title'))
Box.Register('messages_forwardMessage', 0x3f3f4f2, InputPeer('peer'), Int('id'), Long('random_id'))
Box.Register('messages_sendBroadcast', 0x41bb0972, VectorBox(InputUser)('contacts'), String('message'), InputMedia('media'))
Box.Register('messages_getDhConfig', 0x26cf8950, Int('version'), Int('random_length'))
Box.Register('messages_requestEncryption', 0xf64daf43, InputUser('user_id'), Int('random_id'), Bytes('g_a'))
Box.Register('messages_acceptEncryption', 0x3dbc0415, InputEncryptedChat('peer'), Bytes('g_b'), Long('key_fingerprint'))
Box.Register('messages_discardEncryption', 0xedd923c5, Int('chat_id'))
Box.Register('messages_setEncryptedTyping', 0x791451ed, InputEncryptedChat('peer'), Bool('typing'))
Box.Register('messages_readEncryptedHistory', 0x7f4b690a, InputEncryptedChat('peer'), Int('max_date'))
Box.Register('messages_sendEncrypted', 0xa9776773, InputEncryptedChat('peer'), Long('random_id'), Bytes('data'))
Box.Register('messages_sendEncryptedFile', 0x9a901b66, InputEncryptedChat('peer'), Long('random_id'), Bytes('data'), InputEncryptedFile('file'))
Box.Register('messages_sendEncryptedService', 0x32d439a4, InputEncryptedChat('peer'), Long('random_id'), Bytes('data'))
#Box.Register('messages_receivedQueue', 0x55a5bb66, Int('max_qts')) # returns Vector<long>
#Box.Register('messages_readMessageContents', 0x354b5bc2, VectorBox(Int)('id')) # returns Vector<int>
Box.Register('messages_getStickers', 0xae22e045, String('emoticon'), String('hash'))
Box.Register('messages_getAllStickers', 0xaa3bc868, String('hash'))

Box.Register('updates_getState', 0xedd4882a)
Box.Register('updates_getDifference', 0xa041495, Int('pts'), Int('date'), Int('qts'))

Box.Register('photos_updateProfilePhoto', 0xeef579a0, InputPhoto('id'), InputPhotoCrop('crop'))
Box.Register('photos_uploadProfilePhoto', 0xd50f9c88, InputFile('file'), String('caption'), InputGeoPoint('geo_point'), InputPhotoCrop('crop'))
#Box.Register('photos_deletePhotos', 0x87cf7f2f, VectorBox(InputPhoto)('id')) # returns Vector<long>
Box.Register('photos_getUserPhotos', 0xb7ee553c, InputUser('user_id'), Int('offset'), Int('max_id'), Int('limit'))

Box.Register('upload_saveFilePart', 0xb304a621, Long('file_id'), Int('file_part'), Bytes('bytes'))
Box.Register('upload_getFile', 0xe3a6cfb5, InputFileLocation('location'), Int('offset'), Int('limit'))
Box.Register('upload_saveBigFilePart', 0xde7b673d, Long('file_id'), Int('file_part'), Int('file_total_parts'), Bytes('bytes'))

Box.Register('help_getConfig', 0xc4f9186b)
Box.Register('help_getNearestDc', 0x1fb33026)
Box.Register('help_getAppUpdate', 0xc812ac7e, String('device_model'), String('system_version'), String('app_version'), String('lang_code'))
Box.Register('help_saveAppLog', 0x6f02f748, VectorBox(InputAppEvent)('events'))
Box.Register('help_getInviteText', 0xa4a95186, String('lang_code'))
Box.Register('help_getSupport', 0x9cdf08cd)

if __name__ == "__main__":
    Register("test_struct", 0x12345678, Int, Int)

    test_cl = StructByName['test_struct']
    t = test_cl()
    data = Box.Dump(t.Create(123, 456))
    print(hex(int.from_bytes(data, 'big'))[2:].upper())
    x, ln = Box.Parse(data)
    print(x)
    

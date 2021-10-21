# -*- coding:utf-8 -*-

import hashlib
import os
import py_compile
import random
import shutil
import struct
import sys
import zlib
import k2rc4
import k2rsa
import k2timelib
import marshal
import imp

# rsa 개인키를 이용해서 주어진 파일을 암호화하여 KMD 파일을 생성
# 입력값 : src_fname - 암호화 대상 파일
# 리턴값 : kmd 파일 생성 성공 여부
def make_clb_file(target_file, debug=False):

    # 암호화 대상 파일을 컴파일 또는 복사해서 준비한다.
    file = target_file  # 암호화 대상 파일

    if file.split('.')[1] == 'py':  # 파이썬 파일을 컴파일 한다.
        py_compile.compile(file)    # 컴파일
        pyc_name = file+'c'         # 컴파일 이후 파일명
    else:  # 파이썬 파일이 아닐 경우 확장자를 pyc로 하여 복사한다.
        pyc_name = file.split('.')[0]+'.pyc'
        shutil.copy(file, pyc_name)

    # Simple RSA를 사용하기 위해 공개키와 개인키를 로딩한다.
    # 공개키를 로딩한다.
    rsa_public = k2rsa.read_key('engine/plugins/key.pkr')

    # 개인키를 로딩한다.
    rsa_private = k2rsa.read_key('engine/plugins/key.skr')

    if not (rsa_private and rsa_public):  # 키 파일을 찾을 수 없다
        if debug:
            print('ERROR : Canot find the Key files!')
        return False

    # KMD 파일을 생성
    # 헤더 : 시그너처(KAVM)+예약영역 : [[KAVM][[날짜][시간]...]
    # 시그너처(KAVM)을 추가한다.
    file_signature = 'CLBR'

    # 현재 날짜와 시간
    now_date = k2timelib.get_now_date()
    now_time = k2timelib.get_now_time()

    # 날짜와 시간 값을 2Byte로 변경
    byte_date = struct.pack('<H', now_date)
    byte_time = struct.pack('<H', now_time)

    reserved_area = byte_date + byte_time + (chr(0) * 28)  # 예약 영역

    # 날짜/시간 값이 포함된 예약 영역을 만들어 추가
    file_signature += reserved_area

    # 본문 : [[개인키로 암호화한 RC4 키][RC4로 암호화한 파일]]
    random.seed()

    while 1:
        tmp_clb_data = ''  # 임시 본문 데이터

        # RC4 알고리즘에 사용할 128bit 랜덤키 생성
        random_key = ''
        for i in range(16):
            random_key += chr(random.randint(0, 0xff))

        # 생성된 RC4 키를 암호화
        encrypt_key = k2rsa.crypt(random_key, rsa_private)  # 개인키로 암호화
        if len(encrypt_key) != 32:  # 암호화에 오류가 존재하면 다시 생성
            continue

        # 암호화된 RC4 키를 복호화
        decrypt_key = k2rsa.crypt(encrypt_key, rsa_public)  # 공개키로 복호화

        # 생성된 RC4 키에 문제 없음을 확인한다.
        if random_key == decrypt_key and len(random_key) == len(decrypt_key):
            # 개인키로 암호화 된 RC4 키를 임시 버퍼에 추가한다.
            tmp_clb_data += encrypt_key

            # 생성된 pyc 파일 압축하기
            a = open(pyc_name, 'rb').read()
            b = zlib.compress(a)

            rc4_encrypt = k2rc4.RC4()  # RC4 알고리즘 사용
            rc4_encrypt.set_key(random_key)  # RC4 알고리즘에 key를 적용한다.

            # 압축된 pyc 파일 이미지를 RC4로 암호화한다.
            c = rc4_encrypt.crypt(b)

            rc4_encrypt = k2rc4.RC4()  # RC4 알고리즘 사용
            rc4_encrypt.set_key(random_key)  # RC4 알고리즘에 key를 적용한다.

            # 암호화한 압축된 pyc 파일 이미지 복호화하여 결과가 같은지를 확인한다.
            if rc4_encrypt.crypt(c) != b:
                continue

            # 개인키로 암호화 한 압축 된 파일 이미지를 임시 버퍼에 추가한다.
            tmp_clb_data += c

            # 꼬리 : [개인키로 암호화한 MD5x3]
            # 헤더와 본문에 대해 MD5를 3번 연속 구한다.
            md5 = hashlib.md5()
            md5hash = file_signature + tmp_clb_data  # 헤더와 본문을 합쳐서 MD5 계산

            for i in range(3):
                md5.update(md5hash)
                md5hash = md5.hexdigest()

            m = md5hash.decode('hex')

            md5_encrypt = k2rsa.crypt(m, rsa_private)  # MD5 결과를 개인키로 암호화
            if len(md5_encrypt) != 32:  # 암호화에 오류가 존재하면 다시 생성
                continue

            md5_decrypt = k2rsa.crypt(md5_encrypt, rsa_public)  # 암호화횓 MD5를 공개키로 복호화

            if m == md5_decrypt:  # 원문과 복호화 결과가 같은가?
                # 헤더, 본문, 꼬리를 모두 합친다.
                file_signature += tmp_clb_data + md5_encrypt
                break  # 무한 루프 종료

    # KMD 파일을 생성
    # KMD 파일 이름을 만든다.
    split = file.find('.')
    clb_filename = file[0:split] + '.clb'

    try:
        if file_signature:
            # KMD 파일을 생성한다.
            open(clb_filename, 'wb').write(file_signature)

            # pyc 파일은 삭제한다.
            os.remove(pyc_name)

            if debug:
                print('    Success : %-13s ->  %s' % (file, clb_filename))
            return True
        else:
            raise IOError
    except IOError:
        if debug:
            print('    Fail : %s' % file)
        return False

# 주어진 버퍼에 대해 n회 반복해서 MD5 해시 결과를 리턴한다.
# 입력값 : buf    - 버퍼
#         ntimes - 반복 횟수
# 리턴값 : MD5 해시
def repeat_md5(buf, ntimes):
    md5 = hashlib.md5()
    md5hash = buf
    for i in range(ntimes):
        md5.update(md5hash)
        md5hash = md5.hexdigest()

    return md5hash

# KMD 오류 메시지를 정의
class CLB_Error(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

# KMD 관련 상수
class CLBConstants:
    SIGNATURE = 'CLBR'  # 시그너처

    DATE_POSITION = 4  # 날짜 위치
    DATE_LENGTH = 2  # 날짜 크기
    TIME_POSITION = 6  # 시간 위치
    TIME_LENGTH = 2  # 시간 크기

    RESERVED_POSITION = 8  # 예약 영역 위치
    RESERVED_LENGTH = 28  # 예약 영역 크기

    RC4_KEY_POSITION = 36  # RC4 Key 위치
    RC4_KEY_LENGTH = 32  # RC4 Key 길이

    MD5_POSITION = -32  # MD5 위치

# KMD 클래스
class CLB(CLBConstants):
    # 클래스를 초기화 한다.
    # 인자값 : fname - KMD 파일 이름
    #         pu    - 복호화를 위한 공개키
    def __init__(self, file, pu):
        self.file = file  # KMD 파일 이름
        self.date = None  # KMD 파일의 날짜
        self.time = None  # KMD 파일의 시간
        self.body = None  # 복호화 된 파일 내용

        self.encrypted_data = None  # KMD 암호화 된 파일 내용
        self.rsa_public = pu  # RSA 공개키
        self.rc4_key = None  # RC4 키

        if self.file:
            self.decrypt(self.file)  # 파일을 복호화한다.

    # kmd 파일을 복호화
    # 인자값 : fname - KMD 파일 이름
    def decrypt(self, file, debug=False):
        # KMD 파일을 열고 시그너처를 체크한다.
        with open(file, 'rb') as fp:
            if fp.read(4) == self.SIGNATURE:  # KMD 파일이 맞는지 체크 함
                self.encrypted_data = self.SIGNATURE + fp.read()  # 파일을 읽어 들임
            else:
                raise CLB_Error('KMD Header magic not found.')

        # KMD 파일 날짜 읽기
        tmp = self.encrypted_data[self.DATE_POSITION:
                                self.DATE_POSITION + self.DATE_LENGTH]
        self.date = k2timelib.convert_date(struct.unpack('<H', tmp)[0])

        # KMD 파일 시간 읽기
        tmp = self.encrypted_data[self.TIME_POSITION:
                                self.TIME_POSITION + self.TIME_LENGTH]
        self.time = k2timelib.convert_time(struct.unpack('<H', tmp)[0])

        # KMD 파일에서 MD5 읽기
        md5 = self.get_md5()

        # 무결성 체크
        md5hash = repeat_md5(self.encrypted_data[:self.MD5_POSITION], 3)
        if md5 != md5hash.decode('hex'):
            raise CLB_Error('Invalid KMD MD5 hash.')

        # KMD 파일에서 RC4 키 읽기
        self.rc4_key = self.get_rc4_key()

        # KMD 파일에서 본문 읽기
        clb_body = self.get_body()
        if debug:
            print(len(clb_body))

        # 압축 해제하기
        self.body = zlib.decompress(clb_body)
        if debug:
            print(len(self.body))

    # kmd 파일의 rc4 키를 얻는다.
    # 리턴값 : rc4 키
    def get_rc4_key(self):
        clb_rc4_key = self.encrypted_data[self.RC4_KEY_POSITION:
                                self.RC4_KEY_POSITION
                                + self.RC4_KEY_LENGTH]
        return k2rsa.crypt(clb_rc4_key, self.rsa_public)

    # kmd 파일의 body를 얻는다.
    # 리턴값 : body
    def get_body(self):
        clb_body = self.encrypted_data[self.RC4_KEY_POSITION
                                         + self.RC4_KEY_LENGTH
                                         :self.MD5_POSITION]
        r = k2rc4.RC4()
        r.set_key(self.rc4_key)
        return r.crypt(clb_body)

    # kmd 파일의 md5를 얻는다.
    # 리턴값 : md5
    def get_md5(self):
        clb_md5 = self.encrypted_data[self.MD5_POSITION:]
        return k2rsa.crypt(clb_md5, self.rsa_public)

# 주어진 모듈 이름으로 파이썬 코드를 메모리에 로딩한다.
# 입력값 : mod_name - 모듈 이름
#         buf      - 파이썬 코드 (pyc 시그너처 포함)
# 리턴값 : 로딩된 모듈 Object
def memory_loading(mod_name, signature):
    if signature[:4] == '03F30D0A'.decode('hex'):  # puc 시그너처가 존재하는가?
        try:
            code = marshal.loads(signature[8:])  # pyc에서 파이썬 코드를 로딩한다.
            module = imp.new_module(mod_name)  # 새로운 모듈 생성한다.
            exec (code, module.__dict__)  # pyc 파이썬 코드와 모듈을 연결한다.
            sys.modules[mod_name] = module  # 전역에서 사용가능하게 등록한다.

            return module
        except:
            return None
    else:
        return None
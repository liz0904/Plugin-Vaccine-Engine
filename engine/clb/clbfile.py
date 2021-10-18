# -*- coding:utf-8 -*-

import hashlib
import os
import py_compile
import random
import shutil
import struct
import sys
import zlib
import rc4
import rsa
import timelib
import marshal
import imp

# rsa 개인키를 이용해서 주어진 파일을 암호화하여 clb 파일을 생성
# 입력값 : src_fname - 암호화 대상 파일
# 리턴값 : clb 파일 생성 성공 여부
def make_clb(hash_fname, debug=False):

    # 암호화 대상 파일을 컴파일 또는 복사해서 준비한다.
    filename = hash_fname  # 암호화 대상 파일

    if filename.split('.')[1] == 'py':  # 파이썬 파일을 컴파일 한다.
        py_compile.compile(filename)    # 컴파일
        pyc_name = filename + 'c'         # 컴파일 이후 파일명
    else:  # 파이썬 파일이 아닐 경우 확장자를 pyc로 하여 복사한다.
        pyc_name = filename.split('.')[0] + '.pyc'
        shutil.copy(filename, pyc_name)

    # Simple RSA를 사용하기 위해 공개키와 개인키를 로딩한다.
    # 공개키를 로딩한다.
    rsa_public = rsa.read_key('engine/plugins/key.pkr')

    # 개인키를 로딩한다.
    rsa_private = rsa.read_key('engine/plugins/key.skr')

    if not (rsa_private and rsa_public):  # 키 파일을 찾을 수 없다
        if debug:
            print('ERROR : Can not find out key files...')
        return False

    # CLOUDBREAD 파일을 생성
    # 헤더 : 시그너처(CLBR)+예약영역 : [[CLOUDBREAD][[날짜][시간]...]
    # 시그너처(CLBR)을 추가
    clb_signature = 'CLBR'

    # 현재 날짜와 시간
    now_date = timelib.get_now_date()
    now_time = timelib.get_now_time()

    # 날짜와 시간 값을 2Byte로 변경
    byte_date = struct.pack('<H', now_date)
    byte_time = struct.pack('<H', now_time)

    reserve_buf = byte_date + byte_time + (chr(0) * 28)  # 예약 영역

    # 날짜/시간 값이 포함된 예약 영역을 만들어 추가
    clb_signature += reserve_buf

    # 본문 : [[개인키로 암호화한 RC4 키][RC4로 암호화한 파일]]
    random.seed()

    while 1:
        tmp_clb_data = ''  # 임시 본문 데이터

        # RC4 알고리즘에 사용할 128bit 랜덤키 생성
        key = ''
        for i in range(16):
            key += chr(random.randint(0, 0xff))

        # 생성된 RC4 키를 암호화
        encrypt_key = rsa.crypt(key, rsa_private)  # 개인키로 암호화
        if len(encrypt_key) != 32:  # 암호화에 오류가 존재하면 다시 생성
            continue

        # 암호화된 RC4 키를 복호화
        decrypt_key = rsa.crypt(encrypt_key, rsa_public)  # 공개키로 복호화

        # 생성된 RC4 키에 문제 없음을 확인한다.
        if key == decrypt_key and len(key) == len(decrypt_key):
            # 개인키로 암호화 된 RC4 키를 임시 버퍼에 추가한다.
            tmp_clb_data += encrypt_key

            # 생성된 pyc 파일 압축하기
            buf1 = open(pyc_name, 'rb').read()
            buf2 = zlib.compress(buf1)

            encrypt_rc4 = rc4.RC4()  # RC4 알고리즘 사용
            encrypt_rc4.set_key(key)  # RC4 알고리즘에 key를 적용한다.

            # 압축된 pyc 파일 이미지를 RC4로 암호화한다.
            buf3 = encrypt_rc4.crypt(buf2)

            encrypt_rc4 = rc4.RC4()  # RC4 알고리즘 사용
            encrypt_rc4.set_key(key)  # RC4 알고리즘에 key를 적용한다.

            # 암호화한 압축된 pyc 파일 이미지 복호화하여 결과가 같은지를 확인한다.
            if encrypt_rc4.crypt(buf3) != buf2:
                continue

            # 개인키로 암호화 한 압축 된 파일 이미지를 임시 버퍼에 추가한다.
            tmp_clb_data += buf3

            # 꼬리 : [개인키로 암호화한 MD5x3]
            # 헤더와 본문에 대해 MD5를 3번 연속 구한다.
            md5 = hashlib.md5()
            md5hash = clb_signature + tmp_clb_data  # 헤더와 본문을 합쳐서 MD5 계산

            for i in range(3):
                md5.update(md5hash)
                md5hash = md5.hexdigest()

            m = md5hash.decode('hex')

            encrypt_md5 = rsa.crypt(m, rsa_private)  # MD5 결과를 개인키로 암호화
            if len(encrypt_md5) != 32:  # 암호화에 오류가 존재하면 다시 생성
                continue

            decrypt_md5 = rsa.crypt(encrypt_md5, rsa_public)  # 암호화횓 MD5를 공개키로 복호화

            if m == decrypt_md5:  # 원문과 복호화 결과가 같은가?
                # 헤더, 본문, 꼬리를 모두 합친다.
                clb_signature += tmp_clb_data + encrypt_md5
                break  # 무한 루프 종료

    # clb 파일을 생성
    # clb 파일 이름을 만든다.
    separate = filename.find('.')
    clb_filename = filename[0:separate] + '.clb'
    try:
        if clb_signature:
            # clb 파일을 생성
            open(clb_filename, 'wb').write(clb_signature)

            # pyc 파일은 삭제
            os.remove(pyc_name)

            if debug:
                print('    Success : %-13s ->  %s' % (filename, clb_filename))
            return True
        else:
            raise IOError
    except IOError:
        if debug:
            print('    Fail : %s' % filename)
        return False

# 주어진 버퍼에 대해 n회 반복해서 MD5 해시 결과를 리턴
# 입력값 : buf    - 버퍼
#         ntimes - 반복 횟수
# 리턴값 : MD5 해시
def repeat_md5(buf, num_times):
    md5 = hashlib.md5()
    md5hash = buf
    for i in range(num_times):
        md5.update(md5hash)
        md5hash = md5.hexdigest()

    return md5hash

# clb 오류 메시지를 정의
class CLBError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

# clb 관련 상수
class CLBConstraints:
    CLB_SIGNATURE = 'CLBR'  # 시그니처
    CLB_DATE_POSITION = 4  # 날짜 위치
    CLB_DATE_SIZE = 2  # 날짜 크기
    CLB_TIME_POSITION = 6  # 시간 위치
    CLB_TIME_SIZE = 2  # 시간 크기
    CLB_RESERVE_POSITION = 8  # 예약 영역 위치
    CLB_RESERVE_SIZE = 28  # 예약 영역 크기
    CLB_RC4_POSITION = 36  # RC4 Key 위치
    CLB_RC4_SIZE = 32  # RC4 Key 길이
    CLB_MD5_POSITION = -32  # MD5 위치

# CLB 클래스
class CLB(CLBConstraints):
    # 클래스 초기화
    # 인자값 : filename - CLB 파일 이름
    #         key_public    - 복호화를 위한 공개키
    def __init__(self, filename, key_public):
        self.filename = filename  # CLB 파일 이름
        self.date = None  # clb 파일의 날짜
        self.time = None  # clb 파일의 시간
        self.body = None  # 복호화 된 파일 내용

        self.data_clb_encrypt = None  # CLB 암호화 된 파일 내용
        self.rsa_public = key_public  # RSA 공개키
        self.rc4_key = None  # RC4 키

        if self.filename:
            self.decrypt(self.filename)  # 파일을 복호화한다.

    # CLB 파일을 복호화
    # 인자값 : fname - clb 파일 이름
    def decrypt(self, filename, debug=False):
        # CLB 파일을 열고 시그너처를 체크한다.
        with open(filename, 'rb') as fp:
            if fp.read(4) == self.CLB_SIGNATURE:  # CLB 파일이 맞는지 체크 함
                self.data_clb_encrypt = self.CLB_SIGNATURE + fp.read()  # 파일을 읽어 들임
            else:
                raise CLBError('CLB Header not found.')

        # CLB 파일 날짜 읽기
        tmp = self.data_clb_encrypt[self.CLB_DATE_POSITION:
                                self.CLB_DATE_POSITION + self.CLB_DATE_SIZE]
        self.date = timelib.convert_date(struct.unpack('<H', tmp)[0])

        # CLB 파일 시간 읽기
        tmp = self.data_clb_encrypt[self.CLB_TIME_POSITION:
                                self.CLB_TIME_POSITION + self.CLB_TIME_SIZE]
        self.time = timelib.convert_time(struct.unpack('<H', tmp)[0])

        # CLB 파일에서 MD5 읽기
        get_md5 = self.get_md5()

        # 무결성 체크
        md5hash = repeat_md5(self.data_clb_encrypt[:self.CLB_MD5_POSITION], 3)
        if get_md5 != md5hash.decode('hex'):
            raise CLBError('Invalid CLB MD5 hash.')

        # CLB 파일에서 RC4 키 읽기
        self.rc4_key = self.get_rc4_key()

        # CLB 파일에서 본문 읽기
        clb_data = self.get_body()
        if debug:
            print(len(clb_data))

        # 압축 해제
        self.body = zlib.decompress(clb_data)
        if debug:
            print(len(self.body))

    # CLB 파일의 rc4 키를 얻기
    # 리턴값 : rc4 키
    def get_rc4_key(self):
        key = self.data_clb_encrypt[self.CLB_RC4_POSITION:
                                self.CLB_RC4_POSITION
                                + self.CLB_RC4_SIZE]
        return rsa.crypt(key, self.rsa_public)

    # CLB 파일의 body
    # 리턴값 : body
    def get_body(self):
        clb_body = self.data_clb_encrypt[self.CLB_RC4_POSITION
                                           + self.CLB_RC4_SIZE
                                           :self.CLB_MD5_POSITION]
        r = rc4.RC4()
        r.set_key(self.rc4_key)
        return r.crypt(clb_body)

    # CLB 파일의 md5
    # 리턴값 : md5
    def get_md5(self):
        md5 = self.data_clb_encrypt[self.CLB_MD5_POSITION:]
        return rsa.crypt(md5, self.rsa_public)

# 주어진 모듈 이름으로 파이썬 코드를 메모리에 로딩
# 입력값 : mod_name - 모듈 이름
#         buf      - 파이썬 코드 (pyc 시그너처 포함)
# 리턴값 : 로딩된 모듈 Object
def load(module_name, buf):
    if buf[:4] == '03F30D0A'.decode('hex'):  # pyc 시그너처가 존재 여부
        try:
            code = marshal.loads(buf[8:])  # pyc에서 파이썬 코드를 로딩한다.
            module = imp.new_module(module_name)  # 새로운 모듈 생성한다.
            exec (code, module.__dict__)  # pyc 파이썬 코드와 모듈을 연결한다.
            sys.modules[module_name] = module  # 전역에서 사용가능하게 등록한다.

            return module
        except:
            return None
    else:
        return None
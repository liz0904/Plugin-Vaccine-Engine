# -*- coding:utf-8 -*-

# RC4 클래스
# rc4.set_key : 암호 문자열 정의
# rc4.crypt   : 주어진 버퍼 암/복호화
class RC4:
    # 멤버 변수 초기화
    def __init__(self):
        self.S = []
        self.T = []
        self.key = []
        self.k_a = 0
        self.k_b = 0

    # 암호 설정
    # 인자값 : password - rc4의 암호문
    def set_key(self, password):
        for i in range(len(password)):
            self.key.append(ord(password[i]))
        self.init_rc4()

    # 주어진 데이터 암/복호화
    # 인자값 : data - 암/복호화할 데이터
    # 리턴값 : 암/복호화 결과 데이터
    def crypt(self, data):
        str = []

        for i in range(len(data)):
            str.append(ord(data[i]))

        for i in range(len(str)):
            str[i] ^= self.generate_key()

        result_str = ''
        for i in range(len(str)):
            result_str += chr(str[i])

        return result_str

    # rc4 테이블 초기화
    def init_rc4(self):
        # S 초기화
        for i in range(256):
            self.S.append(i)
            self.T.append(self.key[i % len(self.key)])

        # S의 초기 순열 (치환)
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.T[i]) % 256
            self.swap(i, j)

    # 주어진 두 인덱스의 데이터 교환
    def swap(self, i, j):
        tmp = self.S[i]
        self.S[i] = self.S[j]
        self.S[j] = tmp

    # 암/복호화에 필요한 스트림 생성
    def generate_key(self):
        i = self.k_a
        j = self.k_b

        i = (i + 1) % 256
        j = (j + self.S[i]) % 256
        self.swap(i, j)
        t = (self.S[i] + self.S[j]) % 256

        self.k_a = i
        self.k_b = j

        return self.S[t]
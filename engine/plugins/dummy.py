# -*- coding:utf-8 -*-

import os

# KavMain 클래스
class CLBMain:
    # 플러그인 엔진을 초기화
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    def init(self, plugins_path):  # 플러그인 엔진 초기화
        # 진단/치료하는 악성코드 이름
        self.name = 'Dummy-Test-File (not a virus)'
        # 악성코드 패턴 등록
        self.pattern = 'Dummy Engine test file - CloudBread Anti-Virus Project'

        return 0  # 플러그인 엔진 초기화 성공

    # 플러그인 엔진 종료
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    def uninit(self):
        del self.name  # 메모리 해제 (악성코드 이름 관련)
        del self.pattern  # 메모리 해제 (악성코드 패턴)

        return 0  # 플러그인 엔진 종료 성공

    # 악성코드를 검사한다.
    # 입력값 : filehandle  - 파일 핸들
    #         filename    - 파일 이름
    def detect(self, filehandle, filename):
        try:
            fp = open(filename)
            buf = fp.read(len(self.pattern))  # 패턴은 49 Byte 크기
            fp.close()

            # 악성코드 패턴을 비교
            if buf == self.pattern:
                # 악성코드 패턴이 갖다면 결과 값을 리턴한다.
                return True, self.name, 0
        except IOError:
            pass

        # 악성코드를 발견하지 못했음 (악성코드 발견 여부, 악성코드 이름, 악성코드 ID)
        return False, '', -1

    # 악성코드를 치료
    # 입력값 : filename    - 파일 이름
    #        : malware_id - 치료할 악성코드 ID
    def treat(self, filename, malware_id):
        try:
            # 악성코드 진단 결과 악성코드(0)인가?
            if malware_id == 0:
                os.remove(filename)  # 파일 삭제
                return True  # 치료 완료 리턴
        except IOError:
            pass

        return False  # 치료 실패 리턴

    # 진단/치료 가능한 악성코드의 리스트
    # 리턴값 : 악성코드 리스트
    def having_virus_list(self):
        list_view = list()  # 리스트형 변수 선언
        list_view.append(self.name)  # 진단/치료하는 악성코드 이름 등록
        return list_view

    # 플러그인 엔진의 주요 정보
    def getinfo(self):
        info = dict()
        info['author'] = 'Cloudbread'  # 제작자
        info['version'] = '0.0'  # 버전
        info['engine_info'] = 'Dummy Scan Engine'  # 엔진 설명
        info['engine_name'] = 'dummy'  # 엔진 파일 이름
        info['virus_num'] = 1  # 진단/치료 가능한 악성코드 수
        return info
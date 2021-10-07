# -*- coding:utf-8 -*-

import zipfile

# KavMain 클래스
class KavMain:
    # 플러그인 엔진을 초기화
    # 인력값 : plugins_path - 플러그인 엔진의 위치
    def init(self, plugins_path):  # 플러그인 엔진 초기화
        return 0  # 플러그인 엔진 초기화 성공

    # 플러그인 엔진 종료
    # 리턴값 : 0 - 성공, 0 이외의 값 - 실패
    def uninit(self):
        return 0  # 플러그인 엔진 종료 성공

    # 플러그인 엔진의 주요 정보
    def getinfo(self):
        info = dict()

        info['author'] = 'Cloudbread'  # 제작자
        info['version'] = '0.0'  # 버전
        info['title'] = 'zip Scan Engine'  # 엔진 설명
        info['kmd_name'] = 'zip-virus'  # 엔진 파일 이름
        info['sig_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info

    #파일 포멧 분석
    def format(self, filehandle, filename):
        fileformat={}
        mm=filehandle
        if mm[0:4]=='PK\x03\x04':    #파일 헤더 체크
            fileformat['size']=len(mm)  #포멧 주요 정보 저장(크기)

            ret={'ff_zip':format}
            return ret

        return None

    #압축 파일 내부의 파일 목록 얻기
    def arclist(self, filename, fileformat):
        file_scan_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 ZIP 포맷이 있는가?
        if 'ff_zip' in fileformat:
            zfile=zipfile.ZipFile(filename)
            for name in zfile.namelist():
                file_scan_list.append(['arc_zip', name])
            zfile.close()

        return file_scan_list

    #압축 해제
    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        if arc_engine_id=='arc_zip':
            zfile=zipfile.ZipFile(arc_name)
            data=zfile.read(fname_in_arc)
            zfile.close()

            return data
        return None

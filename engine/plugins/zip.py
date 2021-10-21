# -*- coding:utf-8 -*-

import zipfile

# KavMain 클래스
class CLBMain:
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
        a=filehandle
        if a[0:4]=='PK\x03\x04':    #파일 헤더 체크
            fileformat['size']=len(a)  #포멧 주요 정보 저장(크기)

            result={'zip_format':fileformat}
            return result

        return None

    #압축 파일 내부의 파일 목록 얻기
    def zip_struct_list(self, filename, fileformat):
        zip_struct_list = []  # 검사 대상 정보를 모두 가짐

        # 미리 분석된 파일 포맷중에 ZIP 포맷이 있는가?
        if 'zip_format' in fileformat:
            zf=zipfile.ZipFile(filename)
            for i in zf.namelist():
                zip_struct_list.append(['zip', i])
            zf.close()

        return zip_struct_list

    #압축 해제
    def unzip(self, zip_engine_id, zip_file, zipped_file):
        if zip_engine_id== 'zip':
            zfile=zipfile.ZipFile(zip_file)
            data=zfile.read(zipped_file)
            zfile.close()
            return data
        return None

    #리턴값: 압축 성공 여부
    def bool_rezip(self, zip_engine_id, zip_file, file_infos):
        if zip_engine_id== 'zip':
            zf=zipfile.ZipFile(zip_file, 'w')

            for i in file_infos:
                rname=i.get_target_file()  #검사 대상 파일

                try:
                    with open(rname, 'rb') as fp:
                        buf=fp.read()

                        a_name=i.get_zipped_file()
                        zf.writestr(a_name, buf)
                except IOError:
                    pass
            zf.close()
            return True
        return False



# -*- coding:utf-8 -*-

import os
import re
import glob
import shutil
import tempfile

class Files:
    # 클래스를 초기화
    def __init__(self, filename=None, level=0):
        self.filestruct = {}

        if filename:
            self.set_filestruct(filename, level)

    # 파일에 대한 하나의 FileStruct 생성
    # 인자값 : filename - 파일 이름
    def set_filestruct(self, filename, dir):

        self.filestruct['is_zip'] = False  # 압축 여부
        self.filestruct['zip_engine_id'] = -1  # 압축 해제 가능 엔진 ID
        self.filestruct['zip_filename'] = ''  # 실제 압축 파일
        self.filestruct['unzip_filename'] = ''  # 압축해제 대상 파일
        self.filestruct['detect_filename'] = filename  # 검사 대상 파일
        self.filestruct['another_filename'] = ''   # 압축 파일의 내부를 표현하기 위한 파일명

        self.filestruct['root_filename'] = filename  # 출력용
        self.filestruct['is_modify'] = False  # 수정 여부
        self.filestruct['can_rezip'] = False  # 재압축 가능 여부
        self.filestruct['dir'] = dir  # 압축 깊이

    # 파일에 대한 압축 여부를 확인
    def bool_zip(self):  # 압축 여부
        return self.filestruct['is_zip']

    # 압축 해제 가능한 엔진 확인
    def get_zip_engine_id(self):  # 압축 엔진 ID
        return self.filestruct['zip_engine_id']

    # 실제 압축 파일 이름 확인
    # 리턴값 : 실제 압축 파일 이름
    def get_zip_filename(self):  # 실제 압축 파일
        return self.filestruct['zip_filename']

    # 압축 해제 대상 파일명을 확인
    # 리턴값 : 압축해제 대상 파일
    def get_unzip_filename(self):  # 압축해제 대상 파일
        return self.filestruct['unzip_filename']

    # 실제 작업 대상 파일 이름을 확인
    # 리턴값 : 실제 작업 대상 파일
    def get_detect_filename(self):  # 실제 작업 파일 이름
        return self.filestruct['detect_filename']

    # 실제 작업 대상 파일 이름을 저장한다.
    # 입력값 : 실제 작업 대상 파일
    def set_detect_filename(self, fname):  # 실제 작업 파일명을 저장
        self.filestruct['detect_filename'] = fname


    # 최상위 파일 이름 확인
    # 리턴값 : 압축일 경우 압축 파일명
    def get_root_filename(self):  # 압축일 경우 최상위 파일
        return self.filestruct['root_filename']  # 출력용


    # 압축 파일 내부를 표현하기 위한 파일 이름을 확인한다.
    # 리턴값 : 압축 파일 내부 표현 파일 이름
    def get_another_filename(self):
        return self.filestruct['another_filename']

    # 악성코드 치료로 인해 파일이 수정됨 여부를 확인한다.
    # 리턴값 : True or False
    def is_modify(self):  # 수정 여부
        return self.filestruct['is_modify']


    # 악성코드 치료로 파일이 수정 여부를 저장함
    # 입력값 : 수정 여부 (True or False)
    def set_modify(self, modify):  # 수정 여부
        self.filestruct['is_modify'] = modify


    # 악성코드로 치료 후 파일을 재압축 할 수 있는지 여부를 확인한다.
    # 리턴값 : kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    def can_rezip(self):  # 재압축 가능 여부
        return self.filestruct['can_rezip']


    # 압축의 깊이
    # 리턴값 : 0, 1, 2 ...
    def get_dir(self):  # 압축 깊이
        return self.filestruct['dir']

    # 압축의 깊이를 설정한다.
    # 입력값 : level - 압축 깊이
    def set_dir(self, dir):  # 압축 깊이
        self.filestruct['dir'] = dir

    # 주어진 정보로 파일 정보 저장
    # 입력값 : engine_id - 압축 해제 가능 엔진 ID
    #          zfile     - 압축 파일
    #          uzfile     - 압축해제 대상 파일
    #          anotherfile     - 압축 파일의 내부를 표현하기 위한 파일 이름
    #          rootfile     - 마스터 파일 (최상위 파일 이름)
    #          is_modify    - 수정 여부
    #          can_rezip   - 재압축 가능 여부
    #          dir     - 압축 깊이
    def set_zip(self, engine_id, zfile, uzfile, anotherfile, rootfile, is_modify, can_rezip, dir):
        self.filestruct['is_zip'] = True  # 압축 여부
        self.filestruct['zip_engine_id'] = engine_id  # 압축 해제 가능 엔진 ID
        self.filestruct['zip_filename'] = zfile  # 실제 압축 파일
        self.filestruct['unzip_filename'] = uzfile  # 압축해제 대상 파일
        self.filestruct['detect_filename'] = ''  # 검사 대상 파일
        self.filestruct['another_filename'] = anotherfile  # 압축 파일의 내부를 표현하기 위한 파일명
        self.filestruct['root_filename'] = rootfile  # 마스터 파일 (최상위 파일 이름)
        self.filestruct['is_modify'] = is_modify  # 수정 여부
        self.filestruct['can_rezip'] = can_rezip  # 재압축 가능 여부
        self.filestruct['dir'] = dir  # 재압축 깊이
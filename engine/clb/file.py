# -*- coding:utf-8 -*-

import os
import re
import glob
import shutil
import tempfile

class FileStruct:
    # 클래스를 초기화
    def __init__(self, file=None, level=0):
        self.file_structure = {}

        if file:
            self.set_file_structure(file, level)

    # 파일에 대한 하나의 FileStruct 생성
    # 인자값 : filename - 파일 이름
    def set_file_structure(self, file, level):

        self.file_structure['bool_zip'] = False  # 압축 여부
        self.file_structure['zip_engine_id'] = -1  # 압축 해제 가능 엔진 ID
        self.file_structure['zip_file'] = ''  # 실제 압축 파일
        self.file_structure['zipped_file'] = ''  # 압축해제 대상 파일
        self.file_structure['target_file'] = file  # 검사 대상 파일
        self.file_structure['zip_structure_file'] = ''   # 압축 파일의 내부를 표현하기 위한 파일명

        self.file_structure['root_file'] = file  # 출력용
        self.file_structure['bool_modified'] = False  # 수정 여부
        self.file_structure['bool_rezip'] = False  # 재압축 가능 여부
        self.file_structure['level'] = level  # 압축 깊이

    # 파일에 대한 압축 여부를 확인
    def bool_zip(self):  # 압축 여부
        return self.file_structure['bool_zip']

    # 압축 해제 가능한 엔진 확인
    def get_zip_engine_id(self):  # 압축 엔진 ID
        return self.file_structure['zip_engine_id']

    # 실제 압축 파일 이름 확인
    # 리턴값 : 실제 압축 파일 이름
    def get_zip_file(self):  # 실제 압축 파일
        return self.file_structure['zip_file']

    # 압축 해제 대상 파일명을 확인
    # 리턴값 : 압축해제 대상 파일
    def get_zipped_file(self):  # 압축해제 대상 파일
        return self.file_structure['zipped_file']

    # 실제 작업 대상 파일 이름을 확인
    # 리턴값 : 실제 작업 대상 파일
    def get_target_file(self):  # 실제 작업 파일 이름
        return self.file_structure['target_file']

    # 실제 작업 대상 파일 이름을 저장한다.
    # 입력값 : 실제 작업 대상 파일
    def set_target_file(self, fname):  # 실제 작업 파일명을 저장
        self.file_structure['target_file'] = fname


    # 최상위 파일 이름 확인
    # 리턴값 : 압축일 경우 압축 파일명
    def root_file(self):  # 압축일 경우 최상위 파일
        return self.file_structure['root_file']  # 출력용


    # 압축 파일 내부를 표현하기 위한 파일 이름을 확인한다.
    # 리턴값 : 압축 파일 내부 표현 파일 이름
    def get_zip_structure_file(self):
        return self.file_structure['zip_structure_file']

    # 악성코드 치료로 인해 파일이 수정됨 여부를 확인한다.
    # 리턴값 : True or False
    def bool_modified(self):  # 수정 여부
        return self.file_structure['bool_modified']

    # 악성코드 치료로 파일이 수정 여부를 저장함
    # 입력값 : 수정 여부 (True or False)
    def set_bool_modified(self, modify):  # 수정 여부
        self.file_structure['bool_modified'] = modify


    # 악성코드로 치료 후 파일을 재압축 할 수 있는지 여부를 확인한다.
    # 리턴값 : kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    def bool_rezip(self):  # 재압축 가능 여부
        return self.file_structure['bool_rezip']


    # 압축의 깊이
    # 리턴값 : 0, 1, 2 ...
    def get_level(self):  # 압축 깊이
        return self.file_structure['level']

    # 압축의 깊이를 설정한다.
    # 입력값 : level - 압축 깊이
    def set_level(self, level):  # 압축 깊이
        self.file_structure['level'] = level

    # 주어진 정보로 파일 정보 저장
    # 입력값 : engine_id - 압축 해제 가능 엔진 ID
    #          rname     - 압축 파일
    #          fname     - 압축해제 대상 파일
    #          dname     - 압축 파일의 내부를 표현하기 위한 파일 이름
    #          mname     - 마스터 파일 (최상위 파일 이름)
    #          modify    - 수정 여부
    #          can_arc   - 재압축 가능 여부
    #          level     - 압축 깊이
    def set_archive(self, zip_engine_id, zip_file, zipped_file, zip_structure_file, root_file, bool_modified, bool_rezip, level):
        self.file_structure['bool_zip'] = True  # 압축 여부
        self.file_structure['zip_engine_id'] = zip_engine_id  # 압축 해제 가능 엔진 ID
        self.file_structure['zip_file'] = zip_file  # 실제 압축 파일
        self.file_structure['zipped_file'] = zipped_file  # 압축해제 대상 파일
        self.file_structure['target_file'] = ''  # 검사 대상 파일
        self.file_structure['zip_structure_file'] = zip_structure_file  # 압축 파일의 내부를 표현하기 위한 파일명
        self.file_structure['root_file'] = root_file  # 마스터 파일 (최상위 파일 이름)
        self.file_structure['bool_modified'] = bool_modified  # 수정 여부
        self.file_structure['bool_rezip'] = bool_rezip  # 재압축 가능 여부
        self.file_structure['level'] = level  # 재압축 깊이
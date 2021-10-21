# -*- coding:utf-8 -*-

import os
import re
import glob
import shutil
import tempfile

class FileStruct:
    # 클래스를 초기화
    def __init__(self, filename=None, level=0):
        self.__fs = {}

        if filename:
            self.set_default(filename, level)

    # 파일에 대한 하나의 FileStruct 생성
    # 인자값 : filename - 파일 이름
    def set_default(self, filename, level):

        self.__fs['is_arc'] = False  # 압축 여부
        self.__fs['arc_engine_name'] = -1  # 압축 해제 가능 엔진 ID
        self.__fs['arc_filename'] = ''  # 실제 압축 파일
        self.__fs['filename_in_arc'] = ''  # 압축해제 대상 파일
        self.__fs['real_filename'] = filename  # 검사 대상 파일
        self.__fs['additional_filename'] = ''   # 압축 파일의 내부를 표현하기 위한 파일명

        self.__fs['master_filename'] = filename  # 출력용
        self.__fs['is_modify'] = False  # 수정 여부
        self.__fs['can_arc'] = False  # 재압축 가능 여부
        self.__fs['level'] = level  # 압축 깊이

    # 파일에 대한 압축 여부를 확인
    def is_archive(self):  # 압축 여부
        return self.__fs['is_arc']

    # 압축 해제 가능한 엔진 확인
    def get_archive_engine_name(self):  # 압축 엔진 ID
        return self.__fs['arc_engine_name']

    # 실제 압축 파일 이름 확인
    # 리턴값 : 실제 압축 파일 이름
    def get_archive_filename(self):  # 실제 압축 파일
        return self.__fs['arc_filename']

    # 압축 해제 대상 파일명을 확인
    # 리턴값 : 압축해제 대상 파일
    def get_filename_in_archive(self):  # 압축해제 대상 파일
        return self.__fs['filename_in_arc']

    # 실제 작업 대상 파일 이름을 확인
    # 리턴값 : 실제 작업 대상 파일
    def get_filename(self):  # 실제 작업 파일 이름
        return self.__fs['real_filename']

    # 실제 작업 대상 파일 이름을 저장한다.
    # 입력값 : 실제 작업 대상 파일
    def set_filename(self, fname):  # 실제 작업 파일명을 저장
        self.__fs['real_filename'] = fname


    # 최상위 파일 이름 확인
    # 리턴값 : 압축일 경우 압축 파일명
    def get_master_filename(self):  # 압축일 경우 최상위 파일
        return self.__fs['master_filename']  # 출력용


    # 압축 파일 내부를 표현하기 위한 파일 이름을 확인한다.
    # 리턴값 : 압축 파일 내부 표현 파일 이름
    def get_additional_filename(self):
        return self.__fs['additional_filename']

    # 악성코드 치료로 인해 파일이 수정됨 여부를 확인한다.
    # 리턴값 : True or False
    def is_modify(self):  # 수정 여부
        return self.__fs['is_modify']


    # 악성코드 치료로 파일이 수정 여부를 저장함
    # 입력값 : 수정 여부 (True or False)
    def set_modify(self, modify):  # 수정 여부
        self.__fs['is_modify'] = modify


    # 악성코드로 치료 후 파일을 재압축 할 수 있는지 여부를 확인한다.
    # 리턴값 : kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    def can_archive(self):  # 재압축 가능 여부
        return self.__fs['can_arc']


    # 압축의 깊이
    # 리턴값 : 0, 1, 2 ...
    def get_level(self):  # 압축 깊이
        return self.__fs['level']

    # 압축의 깊이를 설정한다.
    # 입력값 : level - 압축 깊이
    def set_level(self, level):  # 압축 깊이
        self.__fs['level'] = level

    # 주어진 정보로 파일 정보 저장
    # 입력값 : engine_id - 압축 해제 가능 엔진 ID
    #          rname     - 압축 파일
    #          fname     - 압축해제 대상 파일
    #          dname     - 압축 파일의 내부를 표현하기 위한 파일 이름
    #          mname     - 마스터 파일 (최상위 파일 이름)
    #          modify    - 수정 여부
    #          can_arc   - 재압축 가능 여부
    #          level     - 압축 깊이
    def set_archive(self, engine_id, rname, fname, dname, mname, modify, can_arc, level):
        self.__fs['is_arc'] = True  # 압축 여부
        self.__fs['arc_engine_name'] = engine_id  # 압축 해제 가능 엔진 ID
        self.__fs['arc_filename'] = rname  # 실제 압축 파일
        self.__fs['filename_in_arc'] = fname  # 압축해제 대상 파일
        self.__fs['real_filename'] = ''  # 검사 대상 파일
        self.__fs['additional_filename'] = dname  # 압축 파일의 내부를 표현하기 위한 파일명
        self.__fs['master_filename'] = mname  # 마스터 파일 (최상위 파일 이름)
        self.__fs['is_modify'] = modify  # 수정 여부
        self.__fs['can_arc'] = can_arc  # 재압축 가능 여부
        self.__fs['level'] = level  # 재압축 깊이
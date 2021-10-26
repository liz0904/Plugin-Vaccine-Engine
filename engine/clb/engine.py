# -*- coding:utf-8 -*-
import glob
import mmap
import os
import StringIO
import datetime
import tempfile
import types

import clbfile
import rsa
import file
import menu

#Engine 클래스
class Engine:
    #클래스 초기화
    def __init__(self, debug=False):
        self.debug=debug    #디버깅 여부

        self.plugins_path=None  #플러그인 경로
        self.clb_files=[]    #우선순위가 기록된 kmd 리스트
        self.clb_modules = []  # 메모리에 로딩된 모듈

        # 플러그 엔진의 가장 최신 시간 값을 가진다.
        # 초기값으로는 1980-01-01을 지정한다.
        self.max_datetime = datetime.datetime(1980, 1, 1, 0, 0, 0, 0)

    #주어진 경로에서 플러그인 엔진 로딩 준비
    def set_plugins(self, plugins_path):
        self.plugins_path=plugins_path  #플러그인 경로 저장

        #공개키 로딩
        public_key = rsa.to_rsa_key(os.path.join(plugins_path, 'key.pkr'))

        if not public_key:
            return False

        #우선순위 알아내기
        priority = self.get_clb_priority(os.path.join(plugins_path, 'cloudbread.clb'), public_key)

        if not priority: #로딩할 kmd 파일이 없을 시
            return False

        if self.debug:
            print("[*] Cloudbread.clb: ")
            print('     ' + str(self.clb_files))


        # 우선순위대로 CLB 파일을 로딩한다.
        for clb_file in self.clb_files:
            clb_path = os.path.join(plugins_path, clb_file)
            decrypt_all=clbfile.CLB(clb_path, public_key)   #모든 kmd 파일을 복호화
            memory_loading=clbfile.memory_loading(clb_file.split('.')[0], decrypt_all.body)

            if memory_loading:  # 메모리 로딩 성공
                self.clb_modules.append(memory_loading)
                # 메모리 로딩에 성공한 KMD에서 플러그 엔진의 시간 값 읽기
                self.get_last_clb_time(decrypt_all)

        if self.debug:
            print("[*] clb_modules: ")
            print('     ' + str(self.clb_modules))
            print("[*] Last updated %s UTC"%self.max_datetime.ctime())

        return True

    # 복호화 된 플러그인 엔진의 빌드 시간 값 중 최신 값을 보관
    # 입력값 : kmd_info - 복호화 된 플러그인 엔진 정보
    def get_last_clb_time(self, clb_info):
        d_y, d_m, d_d = clb_info.date
        t_h, t_m, t_s = clb_info.time
        t_datetime = datetime.datetime(d_y, d_m, d_d, t_h, t_m, t_s)

        if self.max_datetime < t_datetime:
            self.max_datetime = t_datetime

    # 백신 엔진의 인스턴스를 생성
    def create_engine_instance(self):
        engine_instance = EngineInstance(self.plugins_path, self.max_datetime, self.debug)
        if engine_instance.make_instance(self.clb_modules):
            return engine_instance
        else:
            return None

    #플러그인 엔진의 로딩 우선순위 알아내는 함수
    def get_clb_priority(self, cloudbread_kmd_file, pu):
        clb_list=[] #우선순위 목록

        decrypt_cloudbread_clb=clbfile.CLB(cloudbread_kmd_file, pu)    #cloudbread.clb 파일 복호화

        if decrypt_cloudbread_clb.body:  #cloudbread.clb가 읽혔는지?
            msg=StringIO.StringIO(decrypt_cloudbread_clb.body)

            while True:
                line=msg.readline().strip() #엔터 제거

                if not line:    #읽을 내용이 없으면 종료
                    break
                elif line.find('.clb') != -1:   # kmd가 포함되어 있으면 우선순위 목록에 추가
                    clb_list.append(line)
                else:
                    continue

        if len(clb_list):   #우선순위 목록에 하나라도 있다면 성송
            self.clb_files=clb_list
            return True
        else:
            return False


# EngineInstance 클래스
class EngineInstance:
    # 클래스 초기
    # 인자값 : plugins_path - 플러그인 엔진 경로
    #         temp_path    - 임시 폴더 클래스
    #         max_datetime - 플러그인 엔진의 최신 시간 값
    #         debug      - 디버그 여부
    def __init__(self, plugins_path, max_datetime, debug=False):
        self.debug = debug  # 디버깅 여부

        self.plugins_path = plugins_path  # 플러그인 경로
        self.max_datetime = max_datetime  # 플러그 엔진의 가장 최신 시간 값

        self.options={} #옵션
        self.set_options()  #기본 옵션 설정

        self.clbmain_instance=[]    #모든 플러그인의 CLBMain 인스턴스

        self.rezip_info=[]

        self.final_detect={}
        self.identified_virus=set() #유니크한 악성코드 개수를 구하기 위해 사용

    def init(self):
        clb_instance_list=[]   #최종 인스턴스 리스트
        print(len(self.clbmain_instance))

        if self.debug:
            print('[*] CLBMain.init(): ')

        for clb_instance in self.clbmain_instance:
            try:
                #플러그인 엔진 init 함수 호출
                clb_init=clb_instance.init(self.plugins_path)
                if not clb_init:
                    clb_instance_list.append(clb_instance)
                    if self.debug:
                        print('[-] %s.init(): %d' %(clb_instance.__module__, clb_init))
            except AttributeError:
                continue

        self.clbmain_instance=clb_instance_list    #최종 KavMain 인스턴스 등록

        if len(self.clbmain_instance):
            if self.debug:
                print('[*] Count of CLBMain.init(): %d' % (len(self.clbmain_instance)))
            return True
        else:
            return False

    def uninit(self):
        if self.debug:
            print('[*] CLBMain.uninit(): ')

        for clb_instance in self.clbmain_instance:
            try:
                clb_uninit=clb_instance.uninit()
                if self.debug:
                    print('[-] %s.uninit: %d' % (clb_instance.__module__, clb_uninit))
            except AttributeError:
                continue

    def get_info(self):
        engine_info = []  # 플러그인 엔진 정보

        if self.debug:
            print '[*] CLBMain.getinfo() :'

        for instance in self.clbmain_instance:
            try:
                ret = instance.get_info()
                engine_info.append(ret)

                if self.debug:
                    print('    [-] %s.getinfo() :' % instance.__module__)
                    for key in ret.keys():
                        print('        - %-10s : %s' % (key, ret[key]))
            except AttributeError:
                continue

        return engine_info


    # 백신 엔진의 악성코드 검사 결과를 초기화
    def set_final_detect(self):
        self.final_detect['Folders'] = 0  # 폴더 수
        self.final_detect['Files'] = 0  # 파일 수
        self.final_detect['ZIP_Files'] = 0  # 압축 파일 수
        self.final_detect['Detected_Files'] = 0  # 발견된 전체 악성코드 수 (감염)
        self.final_detect['Detected_Viruses'] = 0  # 발견된 유니크한 악성코드 수
        self.final_detect['Treated_Files'] = 0  # 치료한 파일 수
        self.final_detect['Deleted_Files'] = 0  # 삭제한 파일 수
        self.final_detect['IO_errors'] = 0  # 파일 I/O 에러 발생 수

    # 백신 엔진의 악성코드 검사 결과
    def get_result(self):
        # 지금까지 발견한 유티크한 악성코드의 수를 카운트
        self.final_detect['Detected_Viruses'] = len(self.identified_virus)
        return self.final_detect


    # 플러그인 엔진이 진단/치료 할 수 있는 악성코드 목록을 얻음
    # 리턴값 : 악성코드 목록 (콜백함수 사용시 아무런 값도 없음)
    def having_virus_list(self, *callback):
        virus_list = []  # 진단/치료 가능한 악성코드 목록

        argc = len(callback)  # 가변인자 확인

        if argc == 0:  # 인자가 없으면
            cb_fn = None
        elif argc == 1:  # callback 함수가 존재하는지 체크
            cb_fn = callback[0]
        else:  # 인자가 너무 많으면 에러
            return []

        if self.debug:
            print('[*] CLBMain.having_virus_list() :')

        for i in self.clbmain_instance:
            print(i)  # 오류 : 값이 들어가는데 처리가 되지 않음.-----------------------------------------
            try:
                list = i.having_virus_list()

                # callback 함수가 있다면 callback 함수 호출
                if isinstance(cb_fn, types.FunctionType):
                    cb_fn(i.__module__, list)
                else:  # callback 함수가 없으면 악성코드 목록을 누적하여 리턴
                    virus_list += list

                if self.debug:
                    print('    [-] %s.listvirus() :' % i.__module__)
                    for vname in list:
                        print('        - %s' % vname)
            except AttributeError:
                continue

        return virus_list

    # 백신엔진의 인스턴스를 생성
    # 인자값 : kmd_modules - 메모리에 로딩된 KMD 모듈 리스트
    # 리턴값 : 성공 여부
    def make_instance(self, modules):  # 백신 엔진 인스턴스를 생성
        for mod in modules:
            try:
                t = mod.CLBMain()  # 각 플러그인 KavMain 인스턴스 생성
                self.clbmain_instance.append(t)
            except AttributeError:  # KavMain 클래스 존재하지 않음
                continue

        if len(self.clbmain_instance):  # KavMain 인스턴스가 하나라도 있으면 성공
            if self.debug:
                print('[*] Count of CLBMain : %d' % (len(self.clbmain_instance)))
            return True
        else:
            return False

    # 플러그인 엔진에게 악성코드 검사를 요청
    # 입력값 : filename - 악성코 검사 대상 파일 또는 폴더 이름
    #          callback - 검사 시 출력 화면 관련 콜백 함수
    # 리턴값 : 0 - 성공
    #          1 - Ctrl+C를 이용해서 악성코드 검사 강제 종료
    def detect(self, filename, *callback):
        self.rezip_info=[]
        detect_callback=None   #악성코드 검사 콜백 함수
        treat_callback=None  #악성코드 치료 콜백 함수
        done_callback=None #악성코드 압축 최종 치료 콜백 함수

        # 악성코드 검사 결과
        detect_result = {
            'file': '',  # 파일 이름
            'bool_detect': False,  # 악성코드 발견 여부
            'virus': '',  # 발견된 악성코드 이름
            'virus_id': -1,  # 악성코드 ID
            'engine_id': -1  # 악성코드를 발견한 플러그인 엔진 ID
        }

        try:  # 콜백 함수 저장
            detect_callback = callback[0]
            treat_callback = callback[1]
            done_callback = callback[2]
        except IndexError:
            pass

        #가변 인자 확인
        argc=len(callback)

        if argc==1: #callback 함수가 존재하는가?
            cb_fn=callback[0]
        elif argc>1:    #인자가 너무 많으면 에러
            return -1

        #1. 검사 대상 리스트에 파일을 등록
        file_info=file.FileStruct(filename)
        file_detect_list=[file_info]

        while len(file_detect_list):
            try:
                file_list=file_detect_list.pop(0) #검사대상 파일을 하나 가짐
                file_name = file_list.get_target_file()

                # 폴더면 내부 파일리스트만 검사 대상 리스트에 등록
                if os.path.isdir(file_name):
                    if file_name[-1]==os.sep:
                        file_name=file_name[:-1]

                    # 콜백 호출 또는 검사 리턴값 생성
                    detect_result['bool_detect'] = False  # 폴더이므로 악성코드 없음
                    detect_result['file'] = file_name  # 검사 파일 이름
                    detect_result['file_struct'] = file_list  # 검사 파일 이름

                    self.final_detect['Folders'] += 1   #폴더 개수 카운트

                    if self.options['opt_list']:  # 옵션 내용 중 모든 리스트 출력인가?
                        if isinstance(cb_fn, types.FunctionType):   #콜백함수 존재?
                            detect_callback(detect_result)    #콜백함수 호출

                    #폴더 안의 파일들을 검사 대상 리스트에 추가
                    folder_file_list=glob.glob(file_name+os.sep+'*')
                    tmp_folder_file_list=[]

                    for i in folder_file_list:
                        tmp_info=file.FileStruct(i)
                        tmp_folder_file_list.append(tmp_info)

                    file_detect_list=tmp_folder_file_list + file_detect_list

                # 검사 대상이 파일인가? 또는 압축해제 대상인가?
                elif os.path.isfile(file_name) or file_list.bool_zip():
                    self.final_detect['Files'] += 1   #파일 개수 카운트

                    #압축된 파일이면 해제하기
                    unzip_file=self.unzip(file_list)
                    if unzip_file:
                        file_list=unzip_file #압축 결과물이 존재하면 파일정보 교체

                    #2. 포맷 분석
                    file_format=self.analyze_file_format(file_list)

                    #파일로 악성코드 검사
                    unzip_file, virus, virus_id, engine_id=self.detect_zip_file(file_list, file_format)

                    if unzip_file: #악성코드 진단 개수 카운트
                        self.final_detect['Detected_Viruses']+=1
                        self.identified_virus.update([virus])


                    #콜백 호출 또는 검사 리턴값 생성
                    detect_result['bool_detect'] = unzip_file  # 악성코드 발견 여부
                    detect_result['engine_id'] = engine_id  # 엔진 ID
                    detect_result['virus'] = virus  # 에러 메시지로 대체
                    detect_result['virus_id'] = virus_id  # 악성코드 ID
                    detect_result['file_struct']=file_list #검사 파일 이름

                    if detect_result['bool_detect']: #악성코드가 발견 됐다?!
                        if isinstance(detect_callback, types.FunctionType):
                            action_type=detect_callback(detect_result)

                        if action_type == menu.MENU_QUIT:  #종료할거임?
                            return 0
                        self.delete(detect_result, treat_callback, action_type)
                    else:
                        if self.options['opt_list']:  # 모든 리스트 출력인가?
                            if isinstance(detect_callback, types.FunctionType):
                                detect_callback(detect_result)
                        else:   #아니면 악성코드인 것만 출력
                            if detect_result['bool_detect']:
                                if isinstance(cb_fn, types.FunctionType):
                                    detect_callback(detect_result)

                      #압축 파일 최종 치료 정리
                    self.rezip(file_list, done_callback)

                    if not unzip_file:
                        zip_file_list=self.zip_file_list(file_list, file_format)
                        if len(zip_file_list):
                            file_detect_list= zip_file_list + file_detect_list
            except KeyboardInterrupt:
                return 1    #키보드 종료

        self.rezip(None, done_callback, True)   #최종 파일 정리

        return 0    #정상적으로 검사 종료

    def detect_zip_file(self, file_struct, file_format):
        if self.debug:
            print('[*] CLBMain.detect(): ')

        fp=None
        mm=None

        try:
            bool_detect = False
            virus = ''
            virus_id = -1
            engine_id = -1

            file=file_struct.get_target_file() #검사 대상 파일 이름 추출
            filename_ex=file_struct.get_zip_structure_file()   #압축 내부 파일명

            fp=open(file, 'rb')
            mm=mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            for i,inst in enumerate(self.clbmain_instance):
                try:
                    bool_detect,virus, virus_id=inst.detect(mm, file)
                    if bool_detect: #악성코드를 발견하면 추가 악성코드 검사를 중단
                        engine_id=i   #악성코드를 발견한 플러그인 엔진 ID

                        if self.debug:
                            print('[-] %s.detect(): %s' % (inst.__module__, virus))
                            break
                except AttributeError:
                    continue

            if mm:
                mm.close()
            if fp:
                fp.close()

            return bool_detect, virus, virus_id, engine_id
        except IOError:
            self.final_detect['IO_errors'] +=1   #파일 I/O Error 발생수

        return False, '', -1, -1



    # 플러그인 엔진에게 악성코드 치료를 요청한다.
    # 입력값 : filename   - 악성코드 치료 대상 파일 이름
    #          malware_id - 감염된 악성코드 ID
    #          engine_id  - 악성코드를 발견한 플러그인 엔진 ID
    # 리턴값 : 악성코드 치료 성공 여부
    def treat(self, file, virus_id, engine_id):
        bool_treat = False

        if self.debug:
            print('[*] CLBMain.treat() :')

        try:
            # 악성코드를 진단한 플러그인 엔진에게만 치료를 요청
            instance = self.clbmain_instance[engine_id]
            bool_treat = instance.treat(file, virus_id)

            if self.debug:
                print('    [-] %s.treat() : %s' % (instance.__module__, bool_treat))
        except AttributeError:
            pass

        return bool_treat


    def get_version(self):
        return self.max_datetime

    def set_options(self, options=None):
        if options:
            self.options['opt_arc'] = options.opt_arc
            self.options['opt_list']=options.opt_list
        else:
            self.options['opt_arc'] = False
            self.options['opt_list']=False
        return True

    # 진단 가능한 악성코드 수
    def get_virus_num(self):
        virus_num=0 #진단/치료 가능한 악성코드 수

        for i in self.clbmain_instance:
            try:
                tmp=i.get_info()

                if 'virus_num' in tmp:
                    virus_num+=tmp['virus_num']
            except AttributeError:
                continue

        return virus_num

    #플러그인 엔진에게 압축 해제 요청
    def unzip(self, file_struct):
        tmp_file_struct=None

        try:
            if file_struct.bool_zip():
                zip_engine_id=file_struct.get_zip_engine_id()

                zip_file_name=file_struct.get_zip_file()
                zipped_file_name=file_struct.get_zipped_file()

                for i in self.clbmain_instance:
                    try:
                        unzip_body=i.unzip(zip_engine_id, zip_file_name, zipped_file_name)

                        if unzip_body:
                            file=tempfile.mktemp(prefix='ktmp')
                            fp=open(file, 'wb')
                            fp.write(unzip_body)
                            fp.close()

                            tmp_file_struct=file_struct
                            tmp_file_struct.set_target_file(file)

                    except AttributeError:
                        continue
                return tmp_file_struct
        except IOError:
            pass
        return None

    #플러그인 엔진에게 압축파일의 내부 리스트를 요청
    def zip_file_list(self, file_struct, fileformat):
        zip_file_list=[]
        file_detect_list=[]

        target_file=file_struct.get_target_file()
        deep_name=file_struct.get_zip_structure_file()
        root_file=file_struct.root_file()
        level=file_struct.get_level()

        #압축 엔진 모듈의 arclist 멤버 함수 호출
        for i in self.clbmain_instance:

            try:
                if self.options['opt_arc']:
                    zip_file_list=i.zip_struct_list(target_file, fileformat)

                if len(zip_file_list):   #압축 목록이 존재한다면 추가하고 종료
                    for j in zip_file_list:
                        zip_engine_id=j[0] #항상 압축 엔진 ID가 들어옴
                        zip_file_deep=j[1]   #압축 파일의 내부 파일 이름

                        if len (deep_name): #압축 파일 내부 표시용
                            deep_name='%s/%s' %(deep_name, zip_file_deep)
                        else:
                            deep_name='%s' %zip_file_deep

                        fs=file.FileStruct()
                        #기존 level보다 1증가시켜 압축 깊이가 깊어짐을 표시
                        fs.set_archive(zip_engine_id, target_file, zip_file_deep, deep_name, root_file, False, False, level+1)
                        file_detect_list.append(fs)

                    self.final_detect['ZIP_Files']+=1
                    break
            except AttributeError:
                continue

        return file_detect_list

    #플러그인 엔진에게 파일 포맷 분석을 요청
    def analyze_file_format(self, file_struct):
        result={}
        file=file_struct.get_target_file()

        try:
            fp=open(file, 'rb')
            mm=mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            #엔진 모듈의 format 멤버 함수 호출
            for i in self.clbmain_instance:
                try:
                    file_format=i.analyze_file_format(mm, file)
                    if file_format:
                        result.update(file_format)
                except AttributeError:
                    pass
            mm.close()
            fp. close()
        except IOError:
            pass

        return result

    #악성코드를 치료
    def delete(self, detect_result, delete_callback, action_type):
        if action_type==menu.MENU_IGNORE:   #치료 무시
            return

        file_struct=detect_result['file_struct']    #검사 파일 정보
        virus_id=detect_result['virus_id']   #악성코드 ID
        engine_id=detect_result['engine_id']  #악성코드를 진단한 엔진 ID

        target_file=file_struct.get_target_file()
        bool_delete=False

        if action_type==menu.MENU_DISINFECT:    #치료 옵션이 설정됐나?
            bool_delete=self.treat(target_file, virus_id, engine_id)
            if bool_delete:
                self.final_detect['Treated_Files'] +=1    #치료 파일 수
        elif action_type==menu.MENU_DELETE:     #삭제 옵션이 설정 됐나?
            try:
                os.remove(target_file)
                bool_delete=True
                self.final_detect['Deleted_files'] +=1        #삭제 파일 수
            except IOError:
                bool_delete=False

        file_struct.set_bool_modified(bool_delete)   #치료(수정/삭제) 여부 표시

        if isinstance(delete_callback, types.FunctionType):
            delete_callback(detect_result, action_type)


    # update_info 내부의 압축을 처리
    # 입력값 : p_file_info - update_info의 마지막 파일 정보 구조체
    # 리턴값 : 갱신된 파일 정보 구조체
    def rezip_deep(self, file):
        # 실제 압축 파일 이름이 같은 파일을 모두 추출한다.
        ranking = []

        level = file.get_level()

        while len(self.rezip_info):
            if self.rezip_info[-1].get_level() == level:
                ranking.append(self.rezip_info.pop())
            else:
                break

        ranking.reverse()  # 순위를 바꾼다.

        # 리턴값이 될 파일 정보 (압축 파일의 최상위 파일)
        rezip_info_result = self.rezip_info.pop()

        # 업데이트 대상 파일들이 수정 여부를 체크한다
        bool_modify = False

        for i in ranking:
            if i.bool_modified():
                bool_modify = True
                break

        if bool_modify:  # 수정된 파일이 존재한다면 재압축 진행
            zip_file = ranking[0].get_zip_file()
            zip_engine_id = ranking[0].get_zip_engine_id()

            for i in self.clbmain_instance:
                try:
                    bool_rezip=i.bool_rezip(zip_engine_id, zip_file, ranking)
                    if bool_rezip: #최종 압축 성공
                        break
                except AttributeError:
                    continue
            rezip_info_result.set_bool_modified(True)  #수정 여부 표시

        #압축된 파일들 모두 삭제
        for i in ranking:
            target_file=i.get_target_file()
            #플러그인 엔진에 의해 파일이 치료(삭제)됐을 수 있다
            if os.path.exists(target_file):
                os.remove(target_file)

        return rezip_info_result


    # update_info를 갱신
    # 입력값 : file_struct        - 파일 정보 구조체
    #          immediately_flag   - update_info 모든 정보 갱신 여부
    def rezip(self, file_struct, rezip_callback, all_rezip=False):
        # 압축 파일 정보의 재압축을 즉시하지 않고 내부 구성을 확인하여 처리한다.
        if all_rezip is False:
            if len(self.rezip_info) == 0:  # 아무런 파일이 없으면 추가
                self.rezip_info.append(file_struct)
            else:
                now_file = file_struct  # 현재 작업 파일 정보
                last_file = self.rezip_info[-1]  # 직전 파일 정보

                # 마스터 파일이 같은가? (압축 엔진이 있을때만 유효)
                if last_file.root_file() == now_file.root_file():
                    if last_file.get_level() <= now_file.get_level():
                        # 마스터 파일이 같고 계속 압축 깊이가 깊어지면 계속 누적
                        self.rezip_info.append(now_file)
                    else:
                        result_file = self.rezip_deep(last_file)
                        self.rezip_info.append(result_file)  # 결과 파일 추가
                        self.rezip_info.append(now_file)  # 다음 파일 추가
                else:
                    #새로운 파일이 시작되므로 self.update_info 내부 모두 정리
                    all_rezip = True

        # 압축 파일 정보를 이용해 즉시 압축하여 최종 마스터 파일로 재조립한다.
        if all_rezip and len(self.rezip_info) >1:
            result_file=None

            while len(self.rezip_info):
                last_file = self.rezip_info[-1]  # 직전 파일 정보
                result_file = self.rezip_deep(last_file)

                if len(self.rezip_info):  # 최상위 파일이 아니면 하위 결과 추가
                    self.rezip_info.append(result_file)

            if isinstance(rezip_callback, types.FunctionType) and result_file:
                rezip_callback(result_file)
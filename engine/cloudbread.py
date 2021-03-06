# -*- coding:utf-8 -*-

# 실제 임포트 모듈
import os
import sys
from msvcrt import getch
from optparse import OptionParser
import clb.engine
from ctypes import windll, Structure, c_short, c_ushort,  byref

# 주요 상수
VERSION = '0.01'
BUILD_DATE = 'Sep 20 2021'
YEAR = BUILD_DATE[len(BUILD_DATE) - 4:]

gui_options = None  # 옵션

# 콘솔에 색깔 출력을 위한 클래스 및 함수들
FOREGROUND_BLACK = 0x0000
FOREGROUND_BLUE = 0x0001
FOREGROUND_GREEN = 0x0002
FOREGROUND_CYAN = 0x0003
FOREGROUND_RED = 0x0004
FOREGROUND_MAGENTA = 0x0005
FOREGROUND_YELLOW = 0x0006
FOREGROUND_GREY = 0x0007
FOREGROUND_INTENSITY = 0x0008

SHORT = c_short
WORD = c_ushort

class Coord(Structure):
    _fields_ = [
    ("X", SHORT),
    ("Y", SHORT)]

class SmallRect(Structure):
    _fields_ = [
        ("Left", SHORT),
        ("Top", SHORT),
        ("Right", SHORT),
        ("Bottom", SHORT)]

class ConsoleScreenBufferInfo(Structure):
    _fields_ = [
        ("dwSize", Coord),
        ("dwCursorPosition", Coord),
        ("wAttributes", WORD),
        ("srWindow", SmallRect),
        ("dwMaximumWindowSize", Coord)]

# winbase.h
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE = -12

stdout_handle = windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo

def get_text_attr():
    csbi = ConsoleScreenBufferInfo()
    GetConsoleScreenBufferInfo(stdout_handle, byref(csbi))
    return csbi.wAttributes

def set_text_attr(color):
    SetConsoleTextAttribute(stdout_handle, color)

def cprint(msg, color):
    default_colors = get_text_attr()
    default_bg = default_colors & 0x00F0

    set_text_attr(color | default_bg)
    sys.stdout.write(msg)
    set_text_attr(default_colors)

    sys.stdout.flush()

def print_error(msg):
    cprint("Error: ", FOREGROUND_RED|FOREGROUND_INTENSITY)
    print(msg)


def convert_display_filename(real_filename):
    # 출력용 이름
    fsencoding = sys.getfilesystemencoding() or sys.getdefaultencoding()
    display_filename = unicode(real_filename, fsencoding).encode(sys.stdout.encoding,'replace')
    return display_filename

def display_line(filename, message, message_color):
    filename += ' '
    filename = convert_display_filename(filename)
    len_fname = len(filename)
    len_msg = len(message)

    if len_fname + 1 + len_msg < 79:
        fname = '%s' % filename
    else:
        able_size = 79 - len_msg
        able_size -= 5  # ...
        min_size = able_size / 2
        if able_size % 2 == 0:
            fname1 = filename[:min_size-1]
        else:
            fname1 = filename[:min_size]
        fname2 = filename[len_fname - min_size:]

        fname = '%s ... %s' % (fname1, fname2)

    cprint(fname + ' ', FOREGROUND_GREY)
    cprint(message + '\n', message_color)

# 백신 첫화면 출력
def logo():
    logo = '''CloudBread Anti-Virus I (for %s) Ver %s (%s)
    Copyright (C) 2021-%s CloudBread. All rights reserved.
'''

    print('===========================================================')
    a = logo % (sys.platform.upper(), VERSION, BUILD_DATE, YEAR)
    cprint(a, FOREGROUND_CYAN | FOREGROUND_INTENSITY)
    print('===========================================================')


# 파이썬의 옵션 파서 정의 (에러문 제어)
class OptionParsingError(RuntimeError):
    def __init__(self, msg):
        self.msg = msg

class OptionParsingExit(Exception):
    def __init__(self, status, msg):
        self.msg = msg
        self.status = status

class ModifiedOptionParser(OptionParser):
    def error(self, msg):
        raise OptionParsingError(msg)

    def exit(self, status=0, msg=None):
        raise OptionParsingExit(status, msg)

# 백신의 옵션 정의
def define_options():
    usage = "Usage: %prog path[s] [options]"
    parser = ModifiedOptionParser(add_help_option=False, usage=usage)

    parser.add_option("-f", "--files",
                      action="store_true", dest="opt_files",
                      default=True)
    parser.add_option("-r", "--arc",
                      action="store_true", dest="opt_arc",
                      default=False)
    parser.add_option("-I", "--list",
                      action="store_true", dest="opt_list",
                      default=False)
    parser.add_option("-V", "--vlist",
                      action="store_true", dest="opt_vlist",
                      default=False)
    parser.add_option("-p", "--prompt",
                      action="store_true", dest="opt_prompt",
                      default=False)
    parser.add_option("-d", "--dis",
                      action="store_true", dest="opt_dis",
                      default=False)
    parser.add_option("-l", "--del",
                      action="store_true", dest="opt_del",
                      default=False)
    parser.add_option("-?", "--help",
                      action="store_true", dest="opt_help",
                      default=False)

    return parser

#사용법
def usage():
    print('\nUsage: cloudbread.py path[s] [options]')

# 백신 옵션을 분석
def vaccine_options():
    parser = define_options()  # 백신 옵션 정의

    if len(sys.argv) < 2:
        return 'NONE_OPTION', None
    else:
        try:
            (options, args) = parser.parse_args()
            if len(args) == 0:
                return options, None
        except OptionParsingError as e:  # 잘못된 옵션 사용일 경우
            return 'ILLEGAL_OPTION', e.msg
        except OptionParsingExit as e:
            return 'ILLEGAL_OPTION', e.msg

        return options, args


# 백신의 옵션을 출력
def print_options():
    options_string = '''Options:
        -f,  --files           scan files *
        -r,  --zip             scan archives
        -I,  --list            display all files
        -V,  --vlist           display virus list
        -p,  --prompt          prompt for action
        -d,  --dis             disinfect files
        -l,  --del             delete infected files
        -?,  --help            this help
                               * = default option'''

    print(options_string)

# scan의 콜백 함수
def detect_callback(detect_result):
    global gui_options

    file_struct=detect_result['file_struct']

    if len(file_struct.get_zip_structure_file()) !=0:
        name_show = '%s (%s)' % (file_struct.root_file(),
                            file_struct.get_zip_structure_file())
    else:
        name_show='%s'%(file_struct.root_file())

    if detect_result['bool_detect']:
        state = 'detected'

        virus = detect_result['virus']
        message = '%s : %s' %(state, virus)
        message_color = FOREGROUND_RED |FOREGROUND_INTENSITY
    else:
        message = 'ok'
        message_color = FOREGROUND_GREY | FOREGROUND_INTENSITY

    display_line(name_show, message, message_color)

    if gui_options.opt_prompt:     #프롬프트 옵션이 설정되었는가?
        while True and detect_result['bool_detect']:
            cprint('Disinfect/Delete/Ignore/Quie? (d/l/i/q):', FOREGROUND_CYAN |FOREGROUND_INTENSITY)
            ch=getch().lower()
            print ch

            if ch == 'd':
                return clb.menu.MENU_DISINFECT  #악성코드 치료
            elif ch == 'l':
                return clb.menu.MENU_DELETE     #악성코드 삭제
            elif ch == 'i':
                return clb.menu.MENU_IGNORE     #악성코드 치료 무시
            elif ch == 'q':
                return clb.menu.MENU_QUIT
    elif gui_options.opt_dis:  # 치료 옵션
        return clb.menu.MENU_DISINFECT
    elif gui_options.opt_del:  # 삭제 옵션
        return clb.menu.MENU_DELETE

    return clb.menu.MENU_IGNORE #default 값: 악성코드 치료 무시


# disifect의 콜백 함수
def treat_callback(detect_result, action_type):
    fs = detect_result['file_struct']
    message = ''

    if len(fs.get_zip_structure_file()) != 0:
        name_show = '%s (%s)' % (fs.root_file(), fs.get_zip_structure_file())
    else:
        name_show = '%s' % (fs.root_file())

    if fs.bool_modified():  # 수정 성공?
        if action_type == clb.menu.MENU_DISINFECT:
            message = 'treated'
        elif action_type == clb.menu.MENU_DELETE:
            message = 'deleted'

        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY
    else:   #수정 실패
        if action_type == clb.menu.MENU_DISINFECT:
            message = 'treatment failed'
        elif action_type == clb.menu.MENU_DELETE:
            message = 'deletion failed'

        message_color = FOREGROUND_RED | FOREGROUND_INTENSITY

    display_line(name_show, message, message_color)

# update의 콜백 함수
def delete_callback(file):
    if file.bool_modified():  # 수정되었다면 결과 출력
        name_show = file.get_target_file()

        message = 'delete'
        message_color = FOREGROUND_GREEN | FOREGROUND_INTENSITY

        display_line(name_show, message, message_color)



# print_result(result)
# 악성코드 검사 결과를 출력한다.
# 입력값 : result - 악성코드 검사 결과
def print_detect(result):
    print
    print

    cprint('Results:\n', FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Folders             :%d\n' % result['Folders'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Files               :%d\n' % result['Files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Detected Files      :%d\n' % result['Detected_Files'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('Detected Viruses    :%d\n' % result['Detected_Viruses'], FOREGROUND_GREY | FOREGROUND_INTENSITY)
    cprint('I/O errors          :%d\n' % result['IO_errors'], FOREGROUND_GREY | FOREGROUND_INTENSITY)

    print

#listvirus의 콜백함수
def listvirus_callback(plugin_name, vnames):
    for i in vnames:
        print('%-50s [%s.kmd]'%(i, plugin_name))


def main():
    global gui_options

    options, args = vaccine_options()    #옵션 분석
    gui_options=options   #global options 지정

    logo()  #로고 출력

    # 잘못된 옵션인가?
    if options == 'NONE_OPTION':  # 옵션이 없는 경우
        usage()
        print_options()
        return 0
    elif options == 'ILLEGAL_OPTION':  # 정의되지 않은 옵션을 사용한 경우
        usage()
        print('Error: %s' % args)  # 에러 메시지가 담겨 있음
        return 0

    # Help 옵션을 사용한 경우 또는 인자 값이 없는 경우
    if options.opt_help:
        usage()
        print_options()
        return 0

    #백신 엔진 구동
    clb_engine_cls=clb.engine.Engine()    #엔진 클래스
    if not clb_engine_cls.set_plugins('plugins'):   #플러그인 엔진 설정
        print('')
        print_error('CloudBread AntiVirus Engine set_plugins')
        return 0

    clb_engine_inst=clb_engine_cls.create_engine_instance()    #백신 엔진 인스턴스 생성

    if not clb_engine_inst:
        print('')
        print_error('CloudBread AntiVirus Engine create_instance')
        return 0

    if not clb_engine_inst.init():
        print('')
        print_error('CloudBread AntiVirus Engine init')
        return 0

    #엔진 버전 출력
    engine_version=clb_engine_inst.get_version()
    msg='\rLast Updated %s UTC\n'%engine_version.ctime()
    cprint(msg,FOREGROUND_GREY)

    #진단/치료 가능한 악성코드 수 출력
    msg='Signature number: %d\n\n'%clb_engine_inst.get_virus_num()
    cprint(msg, FOREGROUND_GREY)

    clb_engine_inst.set_options(options)    #옵션 설정

    # 악성코드 목록 출력
    if options.opt_vlist is True:
        clb_engine_inst.having_virus_list(listvirus_callback)
    else:
        if args:
            clb_engine_inst.set_final_detect()    #악성코드 검사 결과를 초기화

            #검사용 path
            for scan_path in args:
                scan_path=os.path.abspath(scan_path)

                if os.path.exists(scan_path):   #폴더나 파일이 존재하는가?
                    clb_engine_inst.detect(scan_path, detect_callback)
                else:
                    print_error('Invalid path: \'%s\''%scan_path)

            #악성코드 검사 결과 출력
            show_result=clb_engine_inst.get_result()
            print_detect(show_result)

    clb_engine_inst.uninit()


if __name__=='__main__':
    main()
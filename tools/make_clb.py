# -*- coding:utf-8 -*-

import os
import sys

s = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
) + os.sep + 'Engine' + os.sep + 'clb'

sys.path.append(s)

import clbfile

if __name__=='__main__':
    #인자값 체크
    if len(sys.argv)!=2:
        print("Usage: make_clb.py [python source]")
        exit(0)

    clbfile.make_clb_file(sys.argv[1], True)

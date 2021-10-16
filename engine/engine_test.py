# -*- coding:utf-8 -*-

import os
import sys

import clb.engine

def listvirus_callback(plugin_name, vnames):
    for vname in vnames:
        print("%-50s [%s.kmd]"%(vname, plugin_name))

k2=clb.engine.Engine(debug=True)

if k2.set_plugins('plugins'):
    kav=k2.create_instance()

    if kav:
        print('[*] Success: create_instance')

        ret=kav.init()

        vlist=kav.listvirus(listvirus_callback) #플러그인 바이러스 목록 출력
        print('[*] Used Callback: %d'%len(vlist))

        vlist=kav.listvirus()
        print("[*] Not used Callback: %d"%len(vlist))

        ret, vname, mid, eid = kav.scan('dummy.txt')
        if ret:
            kav.disinfect('dummy.txt', mid, eid)

        kav.uninit()

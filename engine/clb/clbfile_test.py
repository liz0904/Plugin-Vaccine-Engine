# -*- coding:utf-8 -*-

import rsa
import clbfile


#씨이ㅣ이이발 왜 안되노;;

rsa.create_key('key.pkr', 'key.skr')

ret = clbfile.make_clb('../../readme.txt')

if ret:
    pu= rsa.read_key('../plugins/key.pkr')
    k= clbfile.CLB('readme.kmd', pu)
    print(k.body)
else:
    print("fail!")
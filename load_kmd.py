import imp
import marshal
import sys
from engine.clb import rsa, clbfile

pu= rsa.read_key('engine/plugins/key.pkr')
k= clbfile.CLB('dummy.kmd', pu)

code=marshal.loads(k.body[8:])
module=imp.new_module('dummy')
exec(code, module.__dict__)
sys.modules['dummy']=module

print(dir(module))
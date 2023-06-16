#!/usr/bin/env python3
import py_compile
import sys
import zlib
from marshal import dumps

if len(sys.argv) != 3:
    print("USAGE:: %s <py filename> <url>" % sys.argv[0])
    sys.exit(1)

py_filename = sys.argv[1]
url = sys.argv[2]

with open(py_filename,'r') as fd:
    tmp = fd.read()
tmp = tmp.replace('{{https}}', url)
level_1 = compile(tmp, 'level_1','exec')
level_1 = dumps(level_1)

level_2 = b'from marshal import loads\nexec(loads(%r))' % level_1
with open('lvl2.py','wb') as fd:
    fd.write(level_2)
level_2 = compile(level_2, 'level_2','exec')
level_2 = dumps(level_2)

level_3 = b'from marshal import loads\nexec(loads(%r))' % level_2
level_3 = compile(level_3, 'level_2','exec')
level_3 = dumps(level_3)
level_4 = b'from marshal import loads\nimport zlib\nexec(loads(zlib.decompress(%r)))' % zlib.compress(level_3)

out_filename = py_filename[:-3]+'_obf.py'
print("Saving obfuscated python too %s" % out_filename)
with open(out_filename,'wb') as fd:
    fd.write(level_4)

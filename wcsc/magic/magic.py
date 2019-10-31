# static analysis --> scripting :)

import r2pipe

r2 = r2pipe.open("bin1")
r2.cmd('aaaa')
print(r2.cmd("afl~sym.magic"))
print(r2.cmd("s sym.magic"))
print(r2.cmd("pdf 10"))

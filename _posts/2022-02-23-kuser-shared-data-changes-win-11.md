---
title: "Exploit Development: ASLR - Coming To A KUSER_SHARED_DATA Structure Near You!"
date: 2022-02-23
tags: [posts]
excerpt: "Examining recent changes to a highly-abused static structure, KUSER_SHARED_DATA, and its exploitation impact."
---
Introduction
---

A little while back I came across an interesting [tweet](https://twitter.com/rohitwas/status/1442966987198459904?s=20&t=VY_l3TIXBMk1U6juAfGMSQ) that talked about some upcoming changes to `KUSER_SHARED_DATA` on Insider Preview builds of Windows 11.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER1.png" alt="">

This sentiment piqued my interest because `KUSER_SHARED_DATA` is a structure located at a static virtual address, in the traditional Windows kernel, of `0xfffff78000000000`. From an exploitation perspective, this beast of a structure has been abused by adversaries for kernel exploitation, particularly remote kernel exploits, due to its static nature. Although `KUSER_SHARED_DATA` does not contain any interesting pointers to `ntoskrnl.exe`, nor is it executable, there is a section of memory that resides within the same page as `KUSER_SHARED_DATA` that contains no data and, thus, is abusable as a code cave with a static address. 

Taking a look, `KUSER_SHARED_DATA` is `0x738` bytes in size on the latest build of Windows 11 Insider Preview (at the time of this blog post).

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER3.png" alt="">

You may recall on Windows that a given memory "page" is `0x1000` bytes in size, or 4KB. Since `KUSER_SHARED_DATA` is `0x738` bytes in size there are still approximately `0x8C8` bytes of memory available for attackers to abuse. These unused bytes, therefore, still assume the same memory permissions as the rest of `KUSER_SHARED_DATA`, which is that of `RW`, or read/write. This means the "`KUSER_SHARED_DATA` code cave” is a readable and writable code cave which has a static address. [Morten Schenk](https://twitter.com/blomster81) talked about this technique at his BlackHat 2017 talk, and I have also done a previous [blog post](https://connormcgarr.github.io/pte-overwrites/) outlining abusing this structure for code execution.

If this code cave were to be mitigated, an attacker would need to locate another place in memory to place their shellcode. Yes, it is true an adversary with a read/write primitive could corrupt the page table entry (PTE) corresponding to `KUSER_SHARED_DATA` in order to make the page writable. At this point, however, an adversary would have already needed to bypass kASLR and have a primitive to write to memory - meaning that an attacker already has, essentially, full control of the system. Where mitigation of this code cave comes into play is by making exploitation more arduous by _forcing_ adversaries to prove they have a way to bypass kASLR before writing some nefarious code to memory. If an attacker cannot write directly to a static address, the attacker would therefore need to locate some other memory region. Thus, this would be classified as a smaller, more niche mitigation. In any case, I still found this an interesting topic to research.

Lastly, before beginning, this blog post is presented in context of `ntoskrnl.exe` and doesn't translate to the secure kernel in virtual trust level 1 (VTL 1) when Virtualization-Based Security (VBS) is enabled. As Saar Amar [pointed out](https://twitter.com/amarsaar/status/1331744299575341061), this structure is actually randomized in VTL 1.

`0xfffff78000000000` Is Now Read-Only
---

My first thought about possible changes to `KUSER_SHARED_DATA` was that the memory address would finally (somehow) be completely randomized, especially after Saar's previous tweet. To validate this I simply passed in the static address of `KUSER_SHARED_DATA` to the `dt` command in WinDbg and, to my surprise, the structure was still located at `0xfffff78000000000`, after it parsing.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER4.png" alt="">

My next thought was to try and write to `KUSER_SHARED_DATA`, at an offset of `0x800`, to look for any unexpected behavior. It was here I realized that `KUSER_SHARED_DATA` was now read-only, by examining the PTE. 

The address provided below, `0xfffffe7bc0000000`, is the virtual address of the PTE associated with the virtual address `0xfffff78000000000`, or `KUSER_SHARED_DATA`. You can find the address on your system with the command in Windbg `!pte 0xfffff78000000000`. I have omitted these commands for readability of this blog, so as to not keep executing this command over and over again. This blog will inform readers what addresses correspond to what and how to find these addresses on your system.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER5.png" alt="">

This, at first, made sense. However, after talking with my coworker [Yarden Shafir](https://twitter.com/yarden_shafir), there are things in `KUSER_SHARED_DATA`, such as the `SystemTime` member, which are _constantly_ updated and, therefore, Yarden told me to keep digging, as there obviously was some way `KUSER_SHARED_DATA` was being written to/updated with a read-only PTE. This also makes sense, as I found out later, because the `Dirty` bit for the PTE that corresponds with `KUSER_SHARED_DATA` is set to 0, which means the page hasn't been written to. So how exactly is this happening?

Armed with the following information, I went to IDA to look for anything interesting.

`nt!MmWriteableUserSharedData` To The Rescue!
---

After some searching in IDA for references to either `0xfffff78000000000` or terms like "UserShared", I stumbled across a symbol I hadn't seen before - `nt!MmWriteableUserSharedData`. In IDA, this symbol seems to be defined as `0xfffff78000000000`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER6.png" alt="">

However, when looking at a live kernel debugging session, I noticed the address seemed to be different. Not only that, after reboot, this address changed!

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER7.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER8.png" alt="">

We can also see that the static `0xfffff78000000000` address and the new symbol both point to identical memory contents.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER9.png" alt="">

However, I was not yet satisfied. Were these two separate pages pointing to two separate structures that just contained identical contents? Or were they somehow intertwined? After viewing both of the PTEs in tandem, I confirmed that both of these virtual addresses, although different, both leveraged the same page frame number (PFN). The PTE for the “static” `KUSER_SHARED_DATA` and the new symbol `nt!MmWriteableSharedUserData` can be found with the following commands:
1. `!pte 0xfffff78000000000`
2. `!pte poi(nt!MmWriteableSharedUserData)`

As mentioned, the address of the PTE which corresponds with the “static” `KUSER_SHARED_DATA` structure is `0xfffffe7bc0000000`. The address `0xfffffcc340c47010` is the virtual address which corresponds with the PTE of `nt!MmWriteableSharedUserData`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER10.png" alt="">

A PFN multiplied by the size of a page (`0x1000` generally speaking on Windows) will give you the physical address of the corresponding virtual address (in terms of a PTE, the “final” paging structure used to fetch a 4KB-aligned page). Since both of these virtual addresses contain the same PFN, this means that when converting the PFNs to physical addresses (`0xfc1000` in this case), both virtual addresses are backed by the _same_ physical page! We can confirm this by viewing the contents of the physical address backing each virtual address, as well as the virtual addresses themselves.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER11.png" alt="">

What we have here are two virtual addresses, with _different_ memory permissions (one is read-only and the other is read/write) backed by _one_ physical page. In other words, there are two virtual addresses with different _views_ of the same physical memory. How is this possible?

tl;dr - Memory Sections
---
The main “gist” of the changes implemented surrounding `KUSER_SHARED_DATA` is the concept of [memory sections](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/file-backed-and-page-file-backed-sections). What this means is that a section of memory can essentially be shared by two processes (this is true for the kernel, as is in our case). The way this works is that the same physical memory can be mapped to a range of virtual addresses. 

In this case, the new randomized read/write view of `KUSER_SHARED_DATA`, `nt!MmWriteableUserSharedData` (a virtual address) is backed by the same physical memory as the “static” `KUSER_SHARED_DATA` (another virtual address). This means that now there are two “views” of this structure, as seen below

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSERDIAGRAM.png" alt="">

This means that updating one of the virtual addresses (e.g. `nt!MmWriteableSharedUserData`) will update the other virtual address (`0xfffff78000000000`). This is because making a change to one of the virtual addresses will update the physical memory contents. Since the physical memory contents back _both_ virtual addresses, both virtual addresses will receive updates. This provides a method for Windows to keep the old `KUSER_SHARED_DATA` address, while also allowing a new mapped view that is randomized, to “mitigate” the static read/write code cave traditionally found in `KUSER_SHARED_DATA`. The “old” address of `0xfffff78000000000` can now be marked as read-only, as there is a new view of this memory which can be used in its place, which is randomized!

If you were looking for a quick blog to talk about the changes made, that is perfectly okay and I will preface the remainder of this blog by saying that you may stop here if you were looking for a quick rundown of the higher-level details. The rest of this blog will outline the more intricate, lower-level details of the implementation.

If you are interested in how this looks at a bit of a deeper level, in terms of how Windows _actually_ manifested these new updates, like myself, please feel free to read the rest of this blog post! I learned a great amount of technical details in terms of lower-level memory paging concepts, and just wanted to share these thoughts with anyone reading (should anyone care).

`nt!MiProtectSharedUserPage`
---

Before continuing with the analysis, permit me to introduce two terms. When I refer to the memory address `0xfffff78000000000`, the static mapping of `KUSER_SHARED_DATA`, I will use the term “static” `KUSER_SHARED_DATA` from here on out. When I refer to the new “randomized mapping”, I will simply use the symbol name of `nt!MmWriteableSharedUserData`. This will allow me to delineate each time which “version” I am talking about.

After some dynamic analysis in WinDbg, I discovered the answer to my previous question about how these changes to `KUSER_SHARED_DATA` were implemented. I first started by setting a breakpoint on `ntoskrnl.exe` being loaded. It's possible to do this, in an existing kernel debugging session, with the following commands: 
1. `sxe ld nt`
2. `.reboot`

After the breakpoint is hit, we can actually see that the newly-found symbol `nt!MmWriteableUserSharedData` points to the “static” `KUSER_SHARED_DATA` address.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER12.png" alt="">

This is obviously indicative that this symbol is updated further along in the loading process. 

While performing some reverse engineering to identify how this happens, I noticed an interesting cross reference to `nt!MmWriteableSharedUserData` in the function `nt!MiProtectSharedUserPage` via IDA.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER13.png" alt="">

While execution was still paused, as a result of the `ntoskrnl.exe` breakpoint, I set another breakpoint on the aforesaid function `nt!MiProtectSharedUserPage` and confirmed, after reaching the new breakpoint, the `nt!MmWriteableSharedUserData` symbol still pointed to the old `0xfffff78000000000` address.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER14.png" alt="">

Even more interesting, the “static” `KUSER_SHARED_DATA`’ is _still_ static, readable, and writable at this point in the loading process! The below PTE address of `0xffffb7fbc0000000` is the virtual address of the PTE associated with the virtual address of `0xfffff78000000000`. The PTE address has changed due to us rebooting the system as a result of the break-on-load of `ntoskrnl.exe`. As mentioned, this address can always be found on your system with the command `!pte 0xfffff78000000000`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER15.png" alt="">

Since we know `0xfffff78000000000`, the address of the “static” `KUSER_SHARED_DATA` structure, becomes read-only at some point, this is indicative of this function likely being responsible for changing the permissions of this address _AND_ also dynamically filling `nt!MmWriteableSharedUserData`, especially based on naming convention.

Looking deeper into the disassembly of `nt!MiProtectSharedUserPage` we can see that the symbol `nt!MmWriteableSharedUserData` is updated with the value in RDI at the time that this instruction executes. But where does this value come from?

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER16.png" alt="">

Let's take a look at the beginning of the function. The first thing that stands out is the kernel-mode address and calls to `nt!MI_READ_PTE_LOCK_FREE` and `nt!Feature_KernelSharedUserDataAaslr__private_IsEnabled` (which isn't very interesting for our purposes).

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER17.png" alt="">

The kernel-mode address in the image above of `0xfffffb7000000000`, outlined in a red box in the `Disassembly` window of WinDbg , is actually the base of the page table entries (e.g. the address of the PTE array). The second value, the constant of `0x7bc00000000`, is the value used to index this PTE array to fetch the PTE associated with the “static” `KUSER_SHARED_DATA`. This value (the index into the PTE array) can be found with the following formula:
1. Converting the target virtual address (in this case, `0xfffff78000000000`) into a virtual page number (VPN) by dividing the address by the size of a page (`0x1000` in this case)
2. Multiply the VPN by the size of a PTE (64-bit system = 8 bytes)

We can see this by replicating this formula on the virtual address of `0xfffff78000000000`. The resulting value will be the appropriate index into the PTE array to get the PTE associated with the “static” `KUSER_SHARED_DATA`. This can be seen in the `Command` window of WinDbg above.

This means the PTE associated with the “static” `KUSER_SHARED_DATA` is going to be passed in to `nt!MI_READ_PTE_LOCK_FREE`. The address of said PTE is `0xffffb7fbc0000000`.

`nt!MI_READ_PTE_LOCK_FREE`, at a high level, will dereference the contents of the PTE and return them, while also performing a check on the in-scope page table entry to see if it is within the known address space of the PML4E array, which contains an array of PML4 page table entries for usage with the PML4 paging structure. Recall that the PML4 structure is the base paging structure. So, in other words, this ensures that the page table entry provided resides somewhere within the paging structures. This can be seen below.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER18.png" alt="">

However, slightly more nuanced, the function is actually checking to see if the page table entry resides within the “user mode paging structures”, known otherwise as the “shadow space”. Recall that with [KVA Shadow](https://labs.bluefrostsecurity.de/blog/2020/06/30/meltdown-reloaded-breaking-windows-kaslr/)’s implementation, Microsoft’s implementation of Kernel Page-Table Isolation (KPTI), there are now two sets of paging structures: one for kernel mode execution and one for user mode. This mitigation was used to mitigate Meltdown. This check is easily “bypassed”, as the PTE is obviously mapped to a kernel mode address and, thus, not represented by the “user mode paging structures”.

`nt!MI_READ_PTE_LOCK_FREE` then returns the dereferenced contents of the PTE (e.g. the PTE "bits") if the PTE _doesn't_ reside within the “shadow space”. If the PTE does reside in the “shadow space”, there are a few more checks performed on the PTE to determine if KVAS is enabled before the contents are returned. This is not _too_ important for the overall changes we are focusing on, from an exploitation perspective, but still a part of the overall “process”.

Additionally, `nt!Feature_KernelSharedUserDataAslr__private_IsEnabled` isn't very useful to us, except for letting us know we are potentially on the right track by the naming convention. This function mainly seems to be for metrics and telemetry gathering about this feature.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER19.png" alt="">

Earlier, after the first call to `nt!MI_READ_PTE_LOCK_FREE`, the contents of the PTE for the “static” `KUSER_SHARED_DATA` were copied to a stack address - RSP at an offset of `0x20`. This stack address, very similarly, is used in _another_ call to `nt!MI_READ_PTE_LOCK_FREE`. This, again, isn't particularly important to us - but it is part of the process.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER20.png" alt="">

More interestingly, however, is the fact that `nt!MI_READ_PTE_LOCK_FREE` dereferences the PTE contents and returns them via RAX. Since the PTE "bits" for the “static” `KUSER_SHARED_DATA`, which define the memory properties/permissions, are in RAX, they’re then acted upon in the subsequent bitwise-operations to extract the page frame number (PFN) from the PTE of the “static” `KUSER_SHARED_DATA`. This value is `0xf52e` within the PTE, which has a value of `0x800000000000f52e863`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER21.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER22.png" alt="">

This PFN will be leveraged later on in a call to `nt!MiMakeValidPte`. For now, let's move on. 

We can now turn our attention to see that a call to `nt!MiReservePtes` is about to occur.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER23.png" alt="">

Please permit me to quickly provide a brief word on PFN records. A PFN “value” is technically just an abstract value that, when multiplied by `0x1000` (the size of a page), gives us a physical memory address. This is typically either the address of the _next_ paging structure during the memory paging process, or it is used to fetch a final 4KB-aligned physical memory page if being leveraged by the “last” paging table, the PT (page table).

In _addition_ to this, PFN records are also stored in an array of virtual addresses. This array is known as the PFN database. The reason for this is that the memory manager accesses page table entries via linear (virtual) addresses, which increases performance as the MMU does not need to walk all of the paging structures constantly to fetch PFNs, page table entries, etc. This provides an easy way for the records to just be referenced via an index into an array. This goes for all “arrays”, including the PTE array. A function such as `nt!MiGetPteAddress` performs an index into the corresponding page table array, such as the PTE array (for `nt!MiGetPteAddress`, PDE array (PDPT entries, done via `nt!MiGetPdeAddress`), etc.

Knowing this, we can see prior to the call to `nt!MiReservePtes` that the appropriate index into the PFN database that corresponds to the “static” `KUSER_SHARED_DATA` is calculated. This essentially means we are retrieving the virtual address of said PFN record (a `MMPFN` structure) from the PFN database.

We can see this as the base of the PFN database, `0xffffc38000000000` in this case, is involved in the operation. The final virtual address of `0xffffc380002df8a0` (the virtual address of the PFN record associated with the “static” `KUSER_SHARED_DATA`) can be seen below in RBP. It will eventually be used as the second argument in a future function call to `nt!MiMakeProtectionPfnCompatible`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER24.png" alt="">

We can corroborate this by parsing the above virtual address as a `MMPFN` structure to see if the `PteAddress` member corresponds to the known PTE of the “static” `KUSER_SHARED_DATA`. As we know, the PTE is located at `0xffffb7fbc0000000`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSERCONFIRM.png" alt="">

The `PteAddress` member of the PFN structure aligns with the virtual address of the PTE associated with the “static” `KUSER_SHARED_DATA` - thus confirming this is the associated PFN record with the “static” `KUSER_SHARED_DATA`.

This value is then used in a call to `nt!MiReservePtes`, which we can see from two images ago. We know the first argument for this function will go into the RCX register, per the `__fastcall` calling convention. This argument is actually a `nt!_MI_SYSTEM_PTE_TYPE` structure.

According to [CodeMachine](https://codemachine.com/articles/x64_kernel_virtual_address_space_layout.html), when a call to `nt!MiReservePtes` occurs, this structure is used to define what kind of allocation will occur in order to reserve memory for the PTE being created. Allocations, when requested with `nt!MiReservePtes`, may be suggestive of a request to allocate a piece of virtual memory from the System PTE region. The System PTE region is used for mapped views of memory, memory descriptor lists (MDLs), and other items. This information, in combination of our searching for an answer as to how two virtual addresses are backed by the same physical page, is very indicative of different "views" of memory being used (e.g. two virtual addresses correspond to one physical address so both virtual addresses contain the same contents but may have different permissions). Additionally, we can confirm that this allocation is coming from the System PTE region, as the `VaType` member of the `nt!_MI_SYSTEM_PTE_TYPE` structure is set to 9, which is a value in an enumeration that corresponds to `MiVaSystemPtes`. This means the allocation, in this case, will come from the System PTE memory region.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER25.png" alt="">

As we can see after the call occurs, the return value is a kernel-mode address within the same address space of the System PTE region, as defined by the `BasePte` member.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER26.png" alt="">

At this point, the OS has essentially allocated memory from the System PTE region, which is commonly used for mapping multiple views of memory, in the form of an unfilled PTE structure. The next step will be to properly configure this PTE and assign it to a memory address. 

Said process continues with a call to `nt!MiMakeProtectionPfnCompatible`. As previously mentioned, the second argument for this function will be the virtual address of the PFN record, from the PFN database, associated with the PTE that is applied to the “static” `KUSER_SHARED_DATA`. 

The first argument passed to `nt!MiMakeProtectionPfnCompatible` is a constant of 4 (which can be seen 4 screenshots below in the `Command` window of WinDbg). Where does this value come from? Taking a look at [ReactOS](https://github.com/reactos/reactos/blob/f7e8214b5551b67880f3de188d67df26ff9ed2c2/ntoskrnl/inbv/bootanim.c#L18-L19) we can see two constants that are outlined for memory permissions enforced by PTEs.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSERREACTOS1.png" alt="">

According to [ReactOS](https://github.com/reactos/reactos/blob/b0dfe20981065793244a2b8bb6787b441098e715/ntoskrnl/mm/ARM3/miarm.h#L773-L805), there is also a function called `MI_MAKE_HARDWARE_PTE_KERNEL`, which leverages these constants. The prototype and definition can be seen below.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSERREACTOS2.png" alt="">

This function provides a combination of the functionality exposed by both `nt!MiMakeProtectionPfnCompatible` and `nt!MiMakeValidPte` (which is a function we will see shortly). The value 4, or `MM_READWRITE`, is actually [an index into an array](https://github.com/reactos/reactos/blob/1e01afab990b9fb9255d0c0d253ca141d5731a65/ntoskrnl/mm/arm/page.c#L18-L68) called `MmProtectToPteMask`. This array is responsible for converting the requested permission of the page (4, or `MM_READWRITE`) to a PTE-compliant mask.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSERREACTOS3.png" alt="">

We can see the first five elements are as follows: `{0, PTE_READONLY, PTE_EXECUTE, PTE_EXECUTE_READ, PTE_READWRITE}`. From here we can confirm that indexing this array at the index of 4 will retrieve a PTE mask of `PTE_READWRITE`, which are exactly the memory permissions we would like `nt!MmWriteableSharedUserData` to assume, as we know this should be the "new mapped view" of `KUSER_SHARED_DATA`, which is writable. Recall also that the virtual address of the PFN record associated with the “static” `KUSER_SHARED_DATA` is used in the function call, via RDX.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER27.png" alt="">

After the function call, the return value is a “PTE-compatible” mask that represents a readable and writable page.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER29.png" alt="">

At this point we have:
1. An address for our PTE, which is currently empty
2. A "skeleton" for our PTE (e.g. a readable/writable mask to be supplied)

With this in the back of our mind, let's now turn our attention to the call to `nt!MiMakeValidPte`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER30.png" alt="">

`nt!MiMakeValidPte` essentially provides “the rest” of the functionality outlined by the ReactOS function `MI_MAKE_HARDWARE_PTE_KERNEL`. `nt!MiMakeValiePte` requires the following information:
1. Address of the newly created, empty PTE (this PTE will be applied to the virtual address of `nt!MmWriteableUserSharedData`). This is currently in RCX
2. A PFN. This is currently in RDX (e.g. not the virtual address from the PFN database, but the raw PFN "value")
3. A "PTE-compliant" mask (e.g. our read/write attributes). This is currently in R8

All of this information can be seen above in the previous screenshot.

In terms of "mapping different views of the same physical memory", the most important component here is the value in RDX, which is the actual PFN value of `KUSER_SHARED_DATA` (the raw value, not the virtual address). Let's recall first that a PFN, at a high level, is essentially a physical address, when multiplied by the size of a page (`0x1000` bytes, or 4KB). This is true, especially in our case, as we are dealing with the most granular type of memory - a 4KB-aligned piece of memory. There are no more paging structures to index, which is usually what a PFN is used for. This means the PFN, in this case, is used to fetch a final, 4KB-aligned memory page.

We know that the function we are executing inside of (`nt!MiProtectSharedUserPage`) creates a PTE (via `nt!MiReservePtes` and `nt!MiMakeValidPte`). As we know, this PTE will be applied to a virtual address and used to map said virtual address to a physical page, essentially through the PFN associated with the PTE. Currently, the PFN that will be used for this mapping is stored in RDX. At a lower level, this value in RDX multiplied by the size of a page (4KB) will be the actual physical page the virtual address is mapped to.

Interestingly enough, this value in RDX, which was previously preserved after the second call to  `nt!MI_READ_PTE_LOCK_FREE`, is the PFN associated with `KUSER_SHARED_DATA`! In other words, the virtual address we assign this newly created PTE to (which should eventually be `nt!MmWriteableUserSharedData`) will be backed by `KUSER_SHARED_DATA`'s physical memory and, thus, when updates are made to the contents of `nt!MmWriteableUserSharedData` the physical memory backing it will also be updated. Since the “static” `KUSER_SHARED_DATA` (`0xfffff78000000000`) is _also_ backed by THE SAME physical memory it _also_ will receive the updates. Essentially, even though the read-only "static" `KUSER_SHARED_DATA` can't be written to it will _still_ receive updates made by `nt!MmWriteableUserSharedData`, which is readable and writable. This is because both virtual addresses are backed by the same physical memory. Whatever happens to one of these will happen to the other!

Knowing this means that there is no good reason to have the "normal" (e.g. `0xfffff78000000000`) `KUSER_SHARED_DATA` structure address be anything other than read-only, as there is now another memory address that can be used in its place. The benefit here is that the writable "version" or "mapping", `nt!MmWriteableUserSharedData`, is _randomized_!

Moving on now, we are telling the OS we want a valid PTE that is readable and writable, backed by `KUSER_SHARED_DATA`'s PFN (physical address for all intents and purposes), and will be written to the PTE we have already allocated from the System PTE region (since this memory is being used for mapping "views").

After executing the function, we can see this is the case!

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER31.png" alt="">

The next function call, `nt!MiPteInShadowRange`, essentially just does bounds checking to see if our PTE resides in the shadow space. Recall earlier that with the implementation of Kernel Virtual Address Shadow (KVAS) that paging structures are separated: one set for user mode and one set for kernel mode. The “shadow space”, otherwise known as the structures used for user mode addressing, are within the range checked by `nt!MiPteInShadowRange`. Since we are dealing with a kernel mode page, obviously the PTE it is applied to is not within the “shadow space”. It is not really of interest to us for our purposes.

After this function call, a `mov qword ptr [rdi], rbx` instruction occurs. This updates our allocated PTE, which is still blank, with the proper bits created from our call to `nt!MiMakeValidPte`! We now have a valid PTE, backed by the same physical memory as `KUSER_SHARED_DATA` located at the virtual address of `0xfffff78000000000`!

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER32.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER33.png" alt="">

At this point, we are just a few instructions away from our target symbol of `nt!MmWriteableUserSharedData` being updated with the new ASLR’d mapped view of `KUSER_SHARED_DATA`. Then the "static" `KUSER_SHARED_DATA` can be made read-only (recall it is still read/write at this point in the loading process!).

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER34.png" alt="">

Currently, in RDI, we have the address of the PTE we want to use for our new read/write and randomized mapped view of `KUSER_SHARED_DATA` (generated via `nt!MiReservePtes`). The above screenshot shows that there will be some bitwise operations performed on RDI and, as well, we can see that the base of the page table entries will be involved with this operation. These are simply compiler optimizations for converting a given PTE to the virtual address the PTE is applied to.

This is a necessary step, recall, as up until this point we have successfully generated a PTE from the System PTE region and have marked it as read/write, told it to use the “static” `KUSER_SHARED_DATA` as the physical memory backing the virtual memory, but we have not actually applied it to the virtual memory address which will be described and mapped by this PTE! This virtual address we want to apply this PTE to will be the value we want to store in `nt!MmWriteableUserSharedData`!

Let’s again recall the bitwise operations that are in place which will convert the new PTE to the virtual address it backs.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER34.png" alt="">

As we know, we have the target PTE in the RDI register. We know the steps to retrieve the PTE associated with a given virtual address are as follows, which indexes the PTE array appropriately:
1. Convert the virtual address to a virtual page number (VPN) by dividing the virtual address by the size of a page (`0x1000` bytes on a standard Window system)
2. Multiply the above value with the size of a PTE (`0x8` bytes on 64-bit system)
3. Add the value to the base of the page table entry array

This corresponds to indexing the PTE array as follows: `PteBaseArray[VPN]`. Since we know how to go from a virtual address to a PTE, we should be able to reverse these steps to retrieve the virtual address associated with a given PTE.

With PTE in hand, the “reversed” process is as follows:
1. Subtract the PTE array base address from the PTE sitting in RDI (our target PTE) to extract the index into the PTE array
2. Divide the value by the size of a PTE (`0x8` bytes) to retrieve the virtual page number (VPN)
3. Multiply this value by the size of a page (`0x1000`) to retrieve the virtual address

We also know that the compiler generates a `sar rdi, 10h` instruction which will sign extend the value generated from the above steps. If we replicate this process within WinDbg we can see our final value (`0x0000a580a4002000`) would be converted to the address `0xffffa580a4002000`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSERWINDBGCONVERT.png" alt="">

Comparing our computed value with the kernel-produced value, we can see we now have the corresponding virtual address to our PTE, which now is backed by the same physical memory as `KUSER_SHARED_DATA` and both addresses match up to `0xffffa580a4002000`! We can conclude the bitwise operations are part of some macro which converts PTEs to virtual addresses, and this is compiler-optimized code to do so!

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER35.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER36.png" alt="">

This functionality is provided in ReactOS in the form of a [function](https://github.com/reactos/reactos/blob/b0dfe20981065793244a2b8bb6787b441098e715/ntoskrnl/mm/ARM3/miarm.h#L959-L975) called `MI_WRITE_VALID_PTE`. As we can see it essentially not only writes the PTE contents to the PTE address (in this case the allocation from the System PTE region via `nt!MiReservePtes`) but it also fetches the virtual address associated with the PTE through the function `MiPteToAddress`.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSERREACTOS4.png" alt="">

Great! However, there is one last thing we need to do and that is convert the "static" `KUSER_SHARED_DATA` address to read-only. We can already see we are queued up for a call to `nt!MiMakeProtectionPfnCompatible`. In RCX, where the memory permission constant is, we can see a value of 1, or `MM_READONLY` if we recall earlier from when we created a PTE-compliant mask for the read/write mapping of `KUSER_SHARED_DATA`. In other words, the only memory “permissions'' afforded to this page will be read. 

RDX, which contains our index into the PFN array, shows we have the PFN associated with the “static” `KUSER_SHARED_DATA` by comparing the virtual address of the PTE for the “static” `KUSER_SHARED_DATA` (PTE located at `0xffffb7fbc0000000`) to the PTE located in the PFN structure, `MMPFN`. This gives us a PTE-compliant value.

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER37.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER38.png" alt="">

Identically to last time, now just with a read-only page, we setup a call to `nt!MiMakeValidPte` to assign to the "static" `KUSER_SHARED_DATA` read-only permissions, through the virtual address of its PTE (`0xffffb7c000000000`).

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER39.png" alt="">

After the call succeeds, a PTE has been generated for use with pages intended to be read-only. 

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER40.png" alt="">

The "static" `KUSER_SHARED_DATA` gets updated through the same methods aforementioned (the method provided in ReactOS called `MI_WRITE_VALID_PTE`).

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER41.png" alt="">

For our purposes, this is the end of the interesting things that `nt!MiProtectSharedUserPage` does! We now have two virtual addresses that are backed by `KUSER_SHARED_DATA`’s physical memory (one read-only, the "static" `0xfffff78000000000` `KUSER_SHARED_DATA` structure and a new `nt!MmWriteableUserSharedData` version which is randomized and read/write)!

We can now see in IDA, for instance, when `KUSER_SHARED_DATA` needs to be updated, this is done through the new symbol which is randomized and writable. The below image is taken from `nt!KiUpdateTime`, where we can see several offsets of `KUSER_SHARED_DATA` are updated (namely `0x328` and `0x320`). On the same note, in the same photo, we can see that when members from `KUSER_SHARED_DATA` are read, Windows goes through the old "static" hard coded address (in this case, `0xfffff78000000008` and `0xfffff78000000320` in the IDA screenshot).

<img src="{{ site.url }}{{ site.baseurl }}/images/KUSER42.png" alt="">

Exploitability Going Forward and Conclusion
---

Obviously, the same primitive of abusing this code cave no longer will exist, and one of the last (if not the last) static structure has now been mitigated, which attackers have abused in the past. However, with exploitation today, a kASLR bypass is surely needed to gain code execution. This is a smaller mitigation which forces an adversary to prove they can at least bypass kASLR fully in order to write code somewhere reliably. It goes without saying that it would be possible to "bypass" (better word is circumvent, versus "bypassing" the underlying feature), if you write to memory early enough in the kernel loading process via a race condition or some other primitive, to write your code to the static `0xfffff78000000000+0x800` `KUSER_SHARED_DATA` code cave, as we know this structure is still readable and writable when the kernel is first mapped into memory. However, when the kernel fully loads, this region will be read-only. But, nonetheless, it is still possible, due to the initialization happening during the kernel loading. There are public exploits which make use of this primitive, namely my friend and peer [chompie1337's](https://twitter.com/chompie1337) SMBGhost proof-of-concept, so it was definitely worthwhile to pursue to not only raise the bar for attackers, but to break public exploits in their current state. This is a pretty niche change/mitigation, but I thought it nonetheless would be fun to blog about and I learned quite a bit about the System PTE region and memory views along the way.

As always feel free to please reach out with comments, questions, corrections, or suggestions!

Peace, love, and positivity :-)

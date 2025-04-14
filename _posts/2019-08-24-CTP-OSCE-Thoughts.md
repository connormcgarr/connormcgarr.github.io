---
title:  "Riding the NOP sled into OSCE: Retrospect on the _Cracking The Perimeter_ course and OSCE exam"
date:   2019-08-24
tags: [posts]
excerpt: "My thoughts on the Cracking The Perimeter course/OSCE Exam and how I came to learn that one must learn to walk before learning to run."
---
Introduction
---

<img src="{{ site.url }}{{ site.baseurl }}/images/offsec-student-certified-emblem-rgb-osce.png" alt="">

"Can you please update the course materials?" "I'll take this course when the materials are updated!" These are some of the retorts I frequently see, in response to words of commendation and praise that the Offensive Security community attribute to the [_Cracking The Perimeter_](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/) course and [OSCE](https://www.offensive-security.com/information-security-certifications/osce-offensive-security-certified-expert/) exam.

_Cracking The Perimeter_, stylized as _CTP_, is the accompanying course to the Offensive Security Certified Expert (OSCE) certification. Although this course is often seen as "outdated", there is a reason why Offensive Security certifications do not have an expiration date. There is a reason why the courses receive strategic updates. There are reasons why Offensive Security alumni are frequently sought out in the information security market. I will hit on all of the previously mentioned notions, in the middle and latter parts of this post. For now, understand this - there is a reason why Offensive Security has accrued so much notoriety over the years.

What are the prerequisites to this course?
---

Are you an [OSCP](https://www.offensive-security.com/information-security-certifications/oscp-offensive-security-certified-professional/) alumni? Did you take joy in the exploit development portion of the [_PWK_](https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/) course? Do you want to demystify the "magic" behind binary exploitation? Do you just have an overall affection for the exploit development lifecycle, x86 assembly, web applications, and infrastructure exploitation?

If you answered "yes" to any of these questions, this course and exam are probably for you. One thing to note as well, there is a common misconception that one must have the OSCP and/or have completed the PWK course. This is not true. Although beneficial, it is not necessary.

Here are the recommended [prerequisites](https://www.offensive-security.com/ctp-syllabus/#pre-req) to the course.

As stated by Offensive Security, there does need to be a slight tolerance for pain and suffering. They are referring to the fact that indeed, you will be stuck from time to time. Sometimes it may feel like there is no end in sight. Never give up when you feel this way. Read/review until you understand a concept. Utilize your student forums, too! Your fellow peers won't let you go through it alone.

I would recommend dabbling in and being familiar with CPU registers within the x86 (32-bit) architecture, down to the 8-bit registers within them. This [article](https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture) is a good place to start.

I would, in addition, recommend getting intimate with either [Immunity Debugger](https://debugger.immunityinc.com/ID_register.py) or [OllyDbg](http://www.ollydbg.de/download.htm).

What's the content of the course like?
---

The content of the course is heavily focused on Windows exploit development and assembly, after the first two modules.

The full syllabus can be found [here](https://www.offensive-security.com/documentation/cracking-the-perimeter-syllabus.pdf).

After the first two modules, the course focuses on things like: bypassing signature based antivirus applications, backdooring portable executables, fuzzing, [egghunters](https://connormcgarr.github.io/Exception-Handlers-and-Egg-Hunters/), [structured exception handler (SEH) exploits](https://connormcgarr.github.io/Exception-Handlers-and-Egg-Hunters/), alphanumeric shellcode, and Cisco exploitation.

For me, one of the two modules before any assembly/exploit development, that involved manually finding [Local File Inclusion (LFI)](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion) vulnerabilities and chaining them with other attack vectors to obtain remote code execution, was eye opening.

I most enjoyed the modules about the exploit development cycle. This included: fuzzing to identify vulnerabilities, creating POCs, making precise calculations, defeating constrained buffer space, defeating ASLR on Windows Vista, and adhering to specific alphanumeric constraints.

The content of the course really opens your eyes to what goes on under the hood. Slowly but surely, it becomes apparent why the course is designed the way it is.

The exam?
---

I will try not to discourage any readers I may have, but this exam was brutal. I have a short lived information security career at the time of this post, but up until the time this post was written - it is easily the hardest thing I have ever done. In my life.

It is, however, possible.

Although I won't be able to hit on any specifics, there are a small number of objectives that need to be satisfied within the 48 hour allotted time slot. The total amount of points from the objectives is 90, and the successful examinee will be able to acquire 75 of those 90 points.

As far as advice goes, never give up.

There is a reason there is an accompanying course to the exam. Take inspiration from the course, and any research you may have expanded on throughout the course. Think laterally, creatively, and with a purpose.

A few questions I always reiterate to myself when I don't know where else to turn are: "What am I trying to accomplish? What do I already know? How can I expand on what I know? What kinds of questions should I be asking myself, or Google, in order to accomplish this goal?"

tHiS cOuRsE iS sO oUtDaTeD oMg oFfSeC tEaCh mE sOmEtHiNg rElEvAnT!
---

This is the most comical of the comments I see, and where the real ranting will begin.

Why do you think Offensive Security certifications never expire? Why do you think many organizations value any Offensive Security certified personnel, and invest in their training?

The reason is clear. Although there definitely is a lot of technical acumen to be obtained from these courses - the courses are all about the ["Try Harder"](https://www.offensive-security.com/offsec/say-try-harder/) mentality and mindset.

The reason why the Offensive Security certifications don't expire, in my opinion, is this. Anyone who obtained the OSCP when the course was _Penetration with BackTrack_ has the same validity as anyone who took the updated course, _Penetration with Kali Linux_. This is because Offensive Security is aware that anyone who can complete the course at one stage, would be able to do it at any other stage (given the fact they have access to the same resources as students who enroll in updated courses). Offensive Security know the ferocity and vigor that goes into the exams. It’s as much a mind game as it is a test of your technical knowledge. Offensive Security knows that anyone who has the mindset to pass the exams in one variation of the material, would be capable of applying the same techniques, mental focus, and sheer willpower to any other type of material/exam. The exams are designed in such a way that lateral thinking and creativity are just as important, if not more, than the technical aspects of the exams. In all reality, anyone who is persistent enough to obtain the certification in 2009, could replicate the same dedication and discipline in 2039.

The course is called _Cracking the Perimeter_ for a reason. There is so much more out there in the world of offensive security. This course barely scratches the surface - yet is still like drinking from a garden hose. All of the concepts taught in the course, are needed in order to understand modern day exploit mitigations.

How can you run if you don't know how to walk?

OSCE is not a matter the outdated content. It is a matter of understanding the material from the course, along with thinking in multiple dimensions and laterally. That is why these courses are created with the certification challenges. It is so students learn how to apply what they know in effective and creative new ways, not just regurgitate what was memorized in the course.

Although I think that the courses are always valuable, in any state, if Offensive Security updated the OSCE tomorrow - that would be awesome! I would be 100 percent behind it, and I am sure the material would be amazing. However, that does not take away anything from someone who obtained the OSCE if new course materials came along 2 days later. The certification is about actually thinking, and not just tallying up completed objectives.

Remember what competencies are gained from these exams. Not just technical knowledge, but ingenious thinking and being persistent until the job is done. That is why the Offensive Security courses get updated at strategic times, and why the certifications do not expire.

Resources
---

These are not the only things you need to know, but these were the main resources I used:

- [Google](https://www.google.com/)
- [Jumping to shellcode](https://www.abatchy.com/2017/05/jumping-to-shellcode.html)
- [List of x86 opcodes](http://sparksandflames.com/files/x86InstructionChart.html)
- [Types of jumps](http://www.unixwiz.net/techtips/x86-jumps.html)
- [SEH exploits/egghunters](https://connormcgarr.github.io/Exception-Handlers-and-Egg-Hunters/)
- [Aligning the stack/Alphanumeric shellcode 1](https://blog.knapsy.com/blog/2017/05/01/quickzip-4-dot-60-win7-x64-seh-overflow-egghunter-with-custom-encoder/)
- [Aligning the stack/Alphanumeric shellcode 2](https://connormcgarr.github.io/Admin-Express-0day/)
- [HP NNM](https://www.youtube.com/watch?v=gHISpAZiAm0). This is from the creator of the _CTP_ course, [muts](https://twitter.com/muts?lang=en).
- [Windows API docs](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)
- Practice on [Vulnserver](https://github.com/stephenbradshaw/vulnserver). Download the zip and unzip it. Simply run the __.exe__.

If the stack alignment and alphanumeric shellcoding become difficult, it is well explained in the course.

Closing thoughts
---

The thing I took away most from this course was a path to tool independence. This course starts to create a culture of beginning to stop just using tools without a purpose or knowledge of the outcomes. _CTP_ requires you understand what is going on, at the binary level.

The feeling of developing an exploit on your own, is one of the best feelings. The knowledge you gain from understanding shellcoding and the Windows API is very much applicable to modern day payload creation.

In essence, this was an amazing course by Offensive Security, and I highly recommend it. Remember, NEVER GIVE UP AND NEVER GIVE IN! YOU CAN DO IT!

<img src="{{ site.url }}{{ site.baseurl }}/images/OSCE.png" alt="">

Peace, love, and positivity!

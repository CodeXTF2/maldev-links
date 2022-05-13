# maldev-links
My collection of malware dev links + red team tradecraft I picked up over time. Just stuff I found interesting.

https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/ <– interesting macro they used the kernel callback table to execute code
https://gitlab.com/hack-tech/red-team-dev/-/tree/master/DLL_Template_Resource_Loader
https://www.ctus.io/2021/06/29/cause-effect-ive-c2/
https://www.youtube.com/watch?v=vVueJfWmpGc <-- initial access tradecraft
https://enterpriseattack.futuresec.io/enterprise-attack-payload-delivery-webcast
https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/ #activedirectory
https://jackson_t.gitlab.io/walter-planner/ <– attack path mapping
https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/
https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/ #edr #evasion #syscall
https://github.com/chvancooten/NimPackt-v1 <– #payloadgenerator #shellcode
https://gitlab.com/ORCA666/3in1 <— loader
https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop <— more process injection fun
https://github.com/GetRektBoy724/SharpUnhooker <– c# dll unhooker im about to steal lots of code from xD
https://github.com/FatCyclone/D-Pwn <– D/Invoke loaders
https://github.com/cinzinga/Evasion-Practice <– some random stuff to evade sandboxes and stuff
https://www.x86matthew.com/view_post?id=read_write_proc_memory
https://github.com/mgeeky/PackMyPayload
https://youtu.be/qyo6Rmy2odI
https://github.com/ChadMotivation/TymSpecial #shellcoderunner
https://research.checkpoint.com/2022/invisible-cuckoo-cape-sandbox-evasion/ <– another random thing sandboxes didnt simulate properly xd
https://github.com/Inf0secRabbit/BadAssMacros <– might have some features MMG+dN2Js doesnt :eyes:
https://pentestlab.blog/2022/02/14/persistence-notepad-plugins/ #persistence
https://gitlab.com/shodan-public/nrich #osint
https://github.com/cube0x0/KrbRelay <-- KrbRelay
https://www.hawk.io/blog/unicode-reflection-event-null-byte-injection
https://www.x86matthew.com/view_post?id=windows_no_exec <– shellcode exec with no allocating executable memory :thinking:
https://captmeelo.com/redteam/maldev/2022/02/16/libraries-for-maldev.html #another huge maldev library
https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
https://cyber-edge.com/resources/the-endgame-guide-to-threat-hunting/ <-- good to know your enemy
https://github.com/carlospolop/PurplePanda <– About
https://redteaming.co.uk/2021/03/18/sharpedrchecker/ <-- what EDR am I facing? Lets find out!
https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa <-- dynamically stage unhooking code. Nice experiment to try.
https://blog.nviso.eu/2022/02/22/kernel-karnage-part-9-finishing-touches/ <-- NVSIO has good stuff
https://nickzero.co.uk/automating-a-red-team-lab/ <-- RedTeam homelab automation
https://www.trustedsec.com/blog/object-overloading/ <-- Object Overloading
https://www.youtube.com/watch?v=b2L1lWtwBiI&t=1s <– c2 over counter strike game server
https://github.com/mttaggart/OffensiveNotion <– C2 over Notion (the note-taking app)
https://medium.com/@huskyhacks.mk/we-put-a-c2-in-your-notetaking-app-offensivenotion-3e933bace332 <– C2 over Notion (the note-taking app)
https://youtu.be/kO7LlnvE5Rs <– Russian Cyber Attack Escalation in Ukraine - What You Need To Know!
http://essay.utwente.nl/84945/1/__ad.utwente.nl_Org_BA_Bibliotheek_Documentfiles_Afstudeerverslagen__Verwerkt_caretta_crichlow_MA_eemcs.pdf <– blue team’s opsec failures from red POV
https://medium.com/mitre-engage/dive-into-the-mitre-engage-official-release-731504542924 <– MITRE Engage, the MITRE-developed framework for discussing and planning adversary engagement, deception, and denial activities.
https://github.com/RedTeamOperations/Detecting-Adversarial-Tradecrafts-Tools-by-leveraging-ETW
https://github.com/tsale/translated_conti_leaked_comms <– might be interesting to read their conversation and understand their thought process
https://github.com/Cracked5pider/conti_locker <– conti source code if you guys need to do real ransomware testing LOL
https://securityonline.info/tietwagent-etw-based-process-injection-detection/ <– using ETW TI for detection (cant unhook from userland)
https://github.com/curated-intel/Ukraine-Cyber-Operations/ <—cyberwar threat intel we can use to do adversary emulations
https://mrd0x.com/browser-in-the-browser-phishing-attack/
https://www.cisa.gov/uscert/ncas/alerts/aa22-074a Russian State-Sponsored Cyber Actors Gain Network Access by Exploiting Default Multifactor Authentication Protocols and “PrintNightmare” Vulnerability #threatintel report
https://www.x86matthew.com/view_post?id=stack_scraper
https://nickzero.co.uk/automating-a-red-team-lab-part-2/
https://github.com/Azure/caf-terraform-landingzones <– Infra as Code for Azure’s landing zone
https://posts.specterops.io/announcing-azure-in-bloodhound-enterprise-b1a900557cda <– Azure in BloodHound Enterprise
https://github.com/Azure/caf-terraform-landingzones <-- Infra as Code for Azure's landing zone
https://www.youtube.com/watch?v=B2CYOIAFt44&ab_channel=ArnaudLheureux
https://aztfmod.github.io/documentation/ https://github.com/aztfmod/rover
https://medium.com/@bertinjoseb/post-auth-rce-based-in-malicious-lua-plugin-script-upload-scada-controllers-located-in-russia-57044425ac38
https://jwcn-eurasipjournals.springeropen.com/articles/10.1186/s13638-019-1361-0 <– Phishing page detection via learning classifiers from page layout feature
https://phishtank.com/ <– their source of dataset. List of crowd-sourced phishing sites. Some are still active
https://github.com/CoolerVoid/0d1n <– automates web atks
https://medium.com/mitre-engenuity/attack-flow-beyond-atomic-behaviors-c646675cc793 <— cool
https://www.mandiant.com/resources/apt41-us-state-governments
https://posts.specterops.io/revisiting-phishing-simulations-94d9cd460934
https://blog.xenoscr.net/2022/03/12/Implementing-Syscalls-in-Cobalt-Strike-Part-1-Battling-Imports-and-Dependencies.html
https://twitter.com/hardwaterhacker/status/1502425183331799043?s=21
https://blog.xenoscr.net/2022/03/12/Implementing-Syscalls-in-Cobalt-Strike-Part-1-Battling-Imports-and-Dependencies.html
https://techmonitor.ai/policy/geopolitics/the-rise-of-russia-splinternet
https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/ - How EDRs inject DLLs to hook processes
https://ethicalchaos.dev/2020/06/14/lets-create-an-edr-and-bypass-it-part-2/ - Preventing the hook from loading into our process by preventing the DLL load
https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
https://thewover.github.io/Dynamic-Invoke - D/Invoke to avoid sus looking import table from P/Invoke
https://blog.sektor7.net/#!res/2021/halosgate.md - Dynamically resolving syscalls based on unhooked syscalls
Masking malicious memory artifacts - https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-ii-insights-from-moneta
https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners
detecting pid spoofing - https://blog.f-secure.com/detecting-parent-pid-spoofing/
GARGOYLE - https://github.com/y11en/FOLIAGE
Unmanaged .NET - https://blog.xpnsec.com/weird-ways-to-execute-dotnet/https://github.com/countercept/dotnet-gargoyle

 

- https://github.com/mgeeky/ThreadStackSpoofer

- https://www.optiv.com/insights/source-zero/blog/endpoint-detection-and-response-how-hackers-have-evolved -Part1
https://www.optiv.com/insights/source-zero/blog/edr-and-blending-how-attackers-avoid-getting-caught -Part 2

- https://github.com/JLospinoso/gargoyle - good for explaining GARGOYLE, but I didnt understand at first. Needs some knowledge of asm and win internals

- https://github.com/countercept/dotnet-gargoyle - .NET implementation of GARGOYLE

- https://securityonline.info/shellcode-fluctuation-advanced-in-memory-evasion-technique/ - very similar to gargoyle

- https://klezvirus.github.io/RedTeaming/AV_Evasion/CodeExeNewDotNet/
- https://secureyourit.co.uk/wp/2020/11/28/vbafunctionpointers/ - Evading AMSI in VBA

- https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa - Basic EDR evasion and the dynamic EDR unhooking infra, pretty fun
- https://ilankalendarov.github.io/posts/offensive-hooking/ - API hooks for post ex/target monitoring - can steal RDP creds for example

- https://www.arashparsa.com/hook-heaps-and-live-free/ - Heap encryption mainly
- - https://klezvirus.github.io/RedTeaming/AV_Evasion/CodeExeNewDotNet/
https://github.com/klezVirus/inceptor/blob/main/slides/Inceptor%20-%20Bypass%20AV-  Very good article about making a payload generator

- EDR%20solutions%20combining%20well%20known%20techniques.pdf
https://github.com/klezVirus/inceptor

- https://klezvirus.github.io/RedTeaming/AV_Evasion/CodeExeNewDotNet/

- https://github.com/mgeeky/ThreadStackSpoofer


- https://www.optiv.com/insights/source-zero/blog/endpoint-detection-and-response-how-hackers-have-evolved -Part1
https://www.optiv.com/insights/source-zero/blog/edr-and-blending-how-attackers-avoid-getting-caught -Part 2

- https://github.com/JLospinoso/gargoyle - good for explaining GARGOYLE, but I didnt understand at first. Needs some knowledge of asm and win internals

- https://github.com/countercept/dotnet-gargoyle - .NET implementation of GARGOYLE

- https://securityonline.info/shellcode-fluctuation-advanced-in-memory-evasion-technique/ - very similar to gargoyle 
CyberSecurity Blog
The path to code execution in the era of EDR, Next-Gen AVs, and AMSI
Various Posts around Cyber Sec
GitHub
GitHub - klezVirus/inceptor: Template-Driven AV/EDR Evasion Framework
Template-Driven AV/EDR Evasion Framework. Contribute to klezVirus/inceptor development by creating an account on GitHub.
GitHub - klezVirus/inceptor: Template-Driven AV/EDR Evasion Framework
GitHub
GitHub - mgeeky/ThreadStackSpoofer: Thread Stack Spoofing - PoC for...
Thread Stack Spoofing - PoC for an advanced In-Memory evasion technique allowing to better hide injected shellcode&#39;s memory allocation from scanners and analysts. - GitHub - mgeeky/ThreadSt...
GitHub - mgeeky/ThreadStackSpoofer: Thread Stack Spoofing - PoC for...
Optiv
Endpoint Detection and Response: How Hackers Have Evolved
This post identifies systemic endpoint detection and response issues and examines how attackers can bypass any EDR product.
Endpoint Detection and Response: How Hackers Have Evolved
CodeX — 10/21/2021
https://www.reddit.com/r/redteamsec/comments/pu3ejq/sleepycrypt_encrypting_a_running_pe_image_while/
reddit
r/redteamsec - SleepyCrypt: Encrypting a running PE image while it ...
16 votes and 0 comments so far on Reddit
Image
https://www.reddit.com/r/redteamsec/comments/p0m3y4/sleeping_with_a_mask_on_cobalt_strike/
reddit
r/redteamsec - Sleeping with a Mask On (Cobalt Strike)
16 votes and 0 comments so far on Reddit
Image
https://www.reddit.com/r/redteamsec/comments/ocygqf/injector_memory_red_teaming_for_windows/
reddit
r/redteamsec - Injector : Memory red teaming for windows
22 votes and 4 comments so far on Reddit
Image
https://ilankalendarov.github.io/posts/offensive-hooking/ 
Ilan Kalendarov
Offensive API Hooking
Introduction
CodeX — 10/21/2021
https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa
Medium
Adventures in Dynamic Evasion
Most teams I have worked with rely heavily on anecdotal evidence when it comes to evasion. If an operator is asked why they chose a…
Adventures in Dynamic Evasion
https://shogunlab.gitbook.io/building-c2-implants-in-cpp-a-primer/
Introduction
Intro to the book contents and what to expect.
Image
https://secureyourit.co.uk/wp/2020/11/28/vbafunctionpointers/
secureyourit.co.uk
rmdavy.uk
VBA and Function Pointers
https://www.blackarrow.net/hindering-threat-hunting-a-tale-of-evasion-in-a-restricted-environment/
BlackArrow
Hindering Threat Hunting, a tale of evasion in a restricted environ...
Use of Google Apps Script as a proxy for communication with the C&C
Hindering Threat Hunting, a tale of evasion in a restricted environ...
CodeX — 10/21/2021
https://github.com/chinarulezzz/pixload
GitHub
GitHub - chinarulezzz/pixload: Image Payload Creating/Injecting tools
Image Payload Creating/Injecting tools. Contribute to chinarulezzz/pixload development by creating an account on GitHub.
GitHub - chinarulezzz/pixload: Image Payload Creating/Injecting tools
https://github.com/s0md3v/Cloak
GitHub
GitHub - s0md3v/Cloak: Cloak can backdoor any python script with so...
Cloak can backdoor any python script with some tricks. - GitHub - s0md3v/Cloak: Cloak can backdoor any python script with some tricks.
GitHub - s0md3v/Cloak: Cloak can backdoor any python script with so...
https://github.com/redcode-labs/SNOWCRASH
GitHub
GitHub - redcode-labs/SNOWCRASH: A polyglot payload generator
A polyglot payload generator. Contribute to redcode-labs/SNOWCRASH development by creating an account on GitHub.
GitHub - redcode-labs/SNOWCRASH: A polyglot payload generator
CodeX — 10/21/2021
- https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa - Basic EDR evasion and the dynamic EDR unhooking infra, pretty fun
- https://ilankalendarov.github.io/posts/offensive-hooking/ - API hooks for post ex/target monitoring - can steal RDP creds for example

### Research on the weaponization process in red teams
- https://www.youtube.com/watch?v=5W-Nlkh6nhg - very useful for weaponization workflow
- https://gist.github.com/infosecn1nja/04ab2d8ea15f98880bbf7b70168fa3dd - common weaponization formats
Medium
Adventures in Dynamic Evasion
Most teams I have worked with rely heavily on anecdotal evidence when it comes to evasion. If an operator is asked why they chose a…
Adventures in Dynamic Evasion
Ilan Kalendarov
Offensive API Hooking
Introduction
YouTube
Wild West Hackin' Fest
Mike Felch | Modern Red Team Weaponization | WWHF Deadwood 2020
Image
Gist
APT Group/Red Team Weaponization Phase
APT Group/Red Team Weaponization Phase. GitHub Gist: instantly share code, notes, and snippets.
APT Group/Red Team Weaponization Phase
CodeX — 11/01/2021
https://malapi.io/
CodeX — 11/02/2021
https://isc.sans.edu/forums/diary/Guest+Diary+Etay+Nir+Kernel+Hooking+Basics/23155/
Image
CodeX — 11/05/2021
https://adepts.of0x.cc/alternatives-copy-shellcode/
One thousand and one ways to copy your shellcode to memory (VBA Macros) |
One thousand and one ways to copy your shellcode to memory (VBA Mac...
Alternative ways to copy your shellcode to memory in your VBA macros
Image
CodeX — 11/06/2021
https://medium.com/falconforce/bof2shellcode-a-tutorial-converting-a-stand-alone-bof-loader-into-shellcode-6369aa518548
Medium
BOF2shellcode — a tutorial converting a stand-alone BOF loader into...
TL;DR — At FalconForce we love purple teaming, meaning that we engage in both red teaming and blue teaming. For the red teaming we often…
BOF2shellcode — a tutorial converting a stand-alone BOF loader into...
CodeX — 11/18/2021
https://www.deepinstinct.com/blog/evading-antivirus-detection-with-inline-hooks
Deep Instinct
Evading EDR Detection with Reentrancy Abuse | Deep Instinct
In this blog, we’ll explore a new way to exploit reentrancy that can be used to evade the behavioral analysis of EDR and legacy antivirus products.
Evading EDR Detection with Reentrancy Abuse | Deep Instinct
https://capt-meelo.github.io//redteam/maldev/2021/11/18/av-evasion-syswhisper.html #syscalls
Hack.Learn.Share
When You sysWhisper Loud Enough for AV to Hear You
This blog contains write-ups of the things that I researched, learned, and wanted to share to others.
Image
https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf
CodeX — 11/19/2021
https://github.com/oXis/GPUSleep
GitHub
GitHub - oXis/GPUSleep: Move CS beacon to GPU memory when sleeping
Move CS beacon to GPU memory when sleeping. Contribute to oXis/GPUSleep development by creating an account on GitHub.
GitHub - oXis/GPUSleep: Move CS beacon to GPU memory when sleeping
CodeX — 11/24/2021
https://www.contextis.com/en/blog/dynamicwrapperex-windows-api-invocation-from-windows-script-host?utm_source=linkedin&utm_medium=HootsuiteCTXIS&utm_campaign=649c522f-1883-4b51-8712-a299c4a9ac31
Context Information Security
DynamicWrapperEx – Windows API Invocation from Windows Script Host ...
This blog begins with covering some basics of COM, the remaining sections cover how to leverage OLE Automation, x64 standard calling convention, registration-free activation, and some of the limitations and security considerations around the use of such to
https://github.com/kyleavery/TitanLdr/tree/heapencrypt
GitHub
GitHub - kyleavery/TitanLdr at heapencrypt
Cobalt Strike User Defined Reflective Loader (UDRL). Check branches for different functionality. - GitHub - kyleavery/TitanLdr at heapencrypt
GitHub - kyleavery/TitanLdr at heapencrypt
CodeX — 11/28/2021
https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/
Bill Demirkapi's Blog
Abusing Windows’ Implementation of Fork() for Stealthy Memory Opera...
Note: Another researcher recently tweeted about the technique discussed in this blog post, this is addressed in the last section of the blog (warning, spoilers!). To access information about a running process, developers generally have to open a handle to the process through the OpenProcess API specifying a combination of
Abusing Windows’ Implementation of Fork() for Stealthy Memory Opera...
CodeX — 12/11/2021
https://github.com/snovvcrash/DInjector
GitHub
GitHub - snovvcrash/DInjector: Collection of shellcode injection te...
Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL - GitHub - snovvcrash/DInjector: Collection of shellcode injection techniques packed in a D/Invoke weaponized DLL
GitHub - snovvcrash/DInjector: Collection of shellcode injection te...
CodeX — 12/19/2021
https://www.netero1010-securitylab.com/eavsion/alternative-process-injection
Alternative Process Injection
Image
https://gist.github.com/Cracked5pider/8f6196b4da16368318a75ff3b1836195
Gist
Get output from injected reflected dll
Get output from injected reflected dll. GitHub Gist: instantly share code, notes, and snippets.
Get output from injected reflected dll
https://github.com/EspressoCake/NativeFunctionStaticMap/blob/main/Native_API_Resolve.pdf #kernel32 to #ntdll
GitHub
NativeFunctionStaticMap/Native_API_Resolve.pdf at main · EspressoCa...
A *very* imperfect attempt to correlate Kernel32 function calls to native API (Nt/Zw) counterparts/execution flow. - NativeFunctionStaticMap/Native_API_Resolve.pdf at main · EspressoCake/NativeFunc...
NativeFunctionStaticMap/Native_API_Resolve.pdf at main · EspressoCa...
CodeX — 12/31/2021
@NO MORE >:C
CodeX — 01/03/2022
https://github.com/LloydLabs/delete-self-poc delete yourself
GitHub
GitHub - LloydLabs/delete-self-poc: A way to delete a locked file, ...
A way to delete a locked file, or current running executable, on disk. - GitHub - LloydLabs/delete-self-poc: A way to delete a locked file, or current running executable, on disk.
GitHub - LloydLabs/delete-self-poc: A way to delete a locked file, ...
CodeX — 01/04/2022
https://www.cobaltstrike.com/blog/writing-beacon-object-files-flexible-stealthy-and-compatible/ <-- direct syscalls from the real ntdll to bypas syscall detection
Cobalt Strike Research and Development
CoreLabs Research
Writing Beacon Object Files: Flexible, Stealthy, and Compatible | C...
Get several ideas and best practices that will increase the quality of your BOFs with this post covering Cobalt Strike Beacon Object Files using the MinGW compiler on Linux.
Writing Beacon Object Files: Flexible, Stealthy, and Compatible | C...
CodeX — 01/13/2022
https://public.cnotools.studio/bring-your-own-vulnerable-kernel-driver-byovkd/exploits/data-only-attack-neutralizing-etwti-provider
Data Only Attack: Neutralizing EtwTi Provider
Image
CodeX — 02/06/2022
https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop @NO MORE >:C we can play wif dis if u wan do malware dev
GitHub
GitHub - RedTeamOperations/Advanced-Process-Injection-Workshop
Contribute to RedTeamOperations/Advanced-Process-Injection-Workshop development by creating an account on GitHub.
GitHub - RedTeamOperations/Advanced-Process-Injection-Workshop
CodeX — 02/14/2022
https://research.checkpoint.com/2022/invisible-cuckoo-cape-sandbox-evasion/
Check Point Research
Invisible Sandbox Evasion - Check Point Research
Cuckoo and CAPE sandbox evasion in one legitimate Windows API function call? It is possible due to issues we found in Cuckoo and CAPE monitor.
Invisible Sandbox Evasion - Check Point Research
CodeX — 02/15/2022
https://twitter.com/ninjaparanoid/status/1493396083644399616?s=21

Paranoid Ninja (Chetan Nayak #BRC4) (@NinjaParanoid)
Here goes the rollerCoaster ride for Unhooking Sentinel1. #BRC4
1. Find Hashtable & Original Ntdll
2. Find hooked instructions in original ntdll and trace the Syscalls
3. Remove PAGEGUARD from fake ntd1l
4. Read LdrLoadDll from ntd1l
5. Patch Original ntdll's LdrLoadDll
VOILAA!
Likes
288
Image

Twitter•02/15/2022
CodeX — 02/19/2022
https://captmeelo.com/redteam/maldev/2022/02/16/libraries-for-maldev.html
Hack.Learn.Share
Useful Libraries for Malware Development
A list of some easy-to-use libraries and how to use them for malware development.
CodeX — 02/21/2022
ransomdev.pdf
Attachment file type: acrobat
ransomdev.pdf
1.85 MB
CodeX — 02/25/2022
https://blog.nviso.eu/2022/02/22/kernel-karnage-part-9-finishing-touches/
NVISO Labs
Sander Forrer
Kernel Karnage – Part 9 (Finishing Touches)
It’s time for the season finale. In this post we explore several bypasses but also look at some mistakes made along the way. 1. From zero to hero: a quick recap As promised in part 8, I spent…
Image
https://blog.nviso.eu/2022/02/22/kernel-karnage-part-9-finishing-touches/
NVISO Labs
Sander Forrer
Kernel Karnage – Part 9 (Finishing Touches)
It’s time for the season finale. In this post we explore several bypasses but also look at some mistakes made along the way. 1. From zero to hero: a quick recap As promised in part 8, I spent…
Image
CodeX — 02/27/2022
https://youtu.be/3RQb05ITSyk

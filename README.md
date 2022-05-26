# redteam/maldev links
Massive thanks to @janoglezcampos for fixing my trash formatting and categorizing it. Now it wont give you eye cancer.
I sometimes put stuff on [my blog](https://codex-7.gitbook.io/). Existing research I read and find useful will be put here.

## Evasion/Execution techs

* [Process injection sample codes](https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop)
* [KnownDLLs injection](https://www.codeproject.com/Articles/325603/Injection-into-a-Process-Using-KnownDlls)
* [Python library for ML evasion and detection etc](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
* [Massive guide on bypassing anticheat and antidebug - also works in malware against EDRs](https://guidedhacking.com/forums/anticheat-bypass-antidebug-tutorials.46/)
* [SysWhispers is dead, long live SysWhispers!](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)
* [3in1: Project aimed to Bypass Some Av Products, Using Different, Advanced Features](https://gitlab.com/ORCA666/3in1)
* [SharpUnhooker: Automatically Unhook API Hive](https://github.com/GetRektBoy724/SharpUnhooker)
* [D-Pwn: practice AV/EDR evasion with D/Invoke](https://github.com/FatCyclone/D-Pwn)
* [Evasion-Practice: Different evasion techniques/PoCs](https://github.com/cinzinga/Evasion-Practice)
* [Reading and writing remote process data without using ReadProcessMemory / WriteProcessMemory](https://www.x86matthew.com/view_post?id=read_write_proc_memory)
* [SharpEDRChecker: EDR detection](https://redteaming.co.uk/2021/03/18/sharpedrchecker/)
* [Adventures in Dynamic Evasion; unhooking](https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa)
* [Object Overloading](https://www.trustedsec.com/blog/object-overloading/)
* [StackScraper - Capturing sensitive data using real-time stack scanning against a remote process](https://www.x86matthew.com/view_post?id=stack_scraper)
* [Unicode Reflection - Event Null Byte Injection](https://www.hawk.io/blog/unicode-reflection-event-null-byte-injection)
* [WindowsNoExec - Abusing existing instructions to executing arbitrary code without allocating executable memory](https://www.x86matthew.com/view_post?id=windows_no_exec)
* [Implementing Syscalls in Cobalt Strike Part 1 - Battling Imports and Dependencies](https://blog.xenoscr.net/2022/03/12/Implementing-Syscalls-in-Cobalt-Strike-Part-1-Battling-Imports-and-Dependencies.html)
* [Lets Create An EDR… And Bypass It! Part 1: How EDRs inject DLLs to hook processes](https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/)
* [Lets Create An EDR… And Bypass It! Part 2: Preventing the hook from loading into our process by preventing the DLL load](https://ethicalchaos.dev/2020/06/14/lets-create-an-edr-and-bypass-it-part-2/)
* [Combining Direct System Calls and sRDI to bypass AV/EDR](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
* [Emulating Covert Operations - Dynamic Invocation (Avoiding PInvoke & API Hooks)](https://thewover.github.io/Dynamic-Invoke/)
* [Halo's Gate: Dynamically resolving syscalls based on unhooked syscalls](https://blog.sektor7.net/#!res/2021/halosgate.md)
* [Masking Malicious Memory Artifacts – Part III: Bypassing Defensive Scanners](https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners)
* [EDR and Blending In: How Attackers Avoid Getting Caught: Part 2](https://www.optiv.com/insights/source-zero/blog/edr-and-blending-how-attackers-avoid-getting-caught)
* [SleepyCrypt: Encrypting a running  PE  image while it sleeps](https://www.solomonsklash.io/SleepyCrypt-shellcode-to-encrypt-a-running-image.html)
* [Sleeping with a Mask On (Cobalt Strike)](https://adamsvoboda.net/sleeping-with-a-mask-on-cobaltstrike/)
* [Adventures in Dynamic Evasion](https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa)
* [Hindering Threat Hunting, a tale of evasion in a restricted environment](https://www.tarlogic.com/blog/hindering-threat-hunting-a-tale-of-evasion-in-a-restricted-environment/)
* [One thousand and one ways to copy your shellcode to memory (VBA Macros)](https://adepts.of0x.cc/alternatives-copy-shellcode/)
* [Evading EDR Detection with Reentrancy Abuse](https://www.deepinstinct.com/blog/evading-antivirus-detection-with-inline-hooks)
* [When You sysWhisper Loud Enough for AV to Hear You](https://captmeelo.com//redteam/maldev/2021/11/18/av-evasion-syswhisper.html)
* [Attacks on ETW Blind EDR Sensors](https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf)
* [GPUSleep](https://github.com/oXis/GPUSleep)
* [Abusing Windows’ Implementation of Fork() for Stealthy Memory Operations](https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/)
* [Alternative Process Injection](https://www.netero1010-securitylab.com/evasion/alternative-process-injection)
* [Delete-self-poc: A way to delete a locked, or current running executable, on disk](https://github.com/LloydLabs/delete-self-poc)
* [Writing Beacon Object Files: Flexible, Stealthy, and Compatible: Direct syscalls from the real ntdll to bypas syscall detection](https://www.cobaltstrike.com/blog/writing-beacon-object-files-flexible-stealthy-and-compatible/)
* [Unhooking Sentinel1](https://twitter.com/ninjaparanoid/status/1493396083644399616?s=21)
* [Kernel Karnage – Part 9 (Finishing Touches)](https://blog.nviso.eu/2022/02/22/kernel-karnage-part-9-finishing-touches/)
* [Using the kernel callback table to execute code](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)
* [Invisible Sandbox Evasion](https://research.checkpoint.com/2022/invisible-cuckoo-cape-sandbox-evasion/)
* [Important: Reduce ur entropy](https://twitter.com/hardwaterhacker/status/1502425183331799043?s=21)

## Operational stuff - OPSEC, TTPs, etc.

* [Parent-child process strcuture](https://mrd0x.com/introduction-to-parent-child-process-evasion/)

## Campaign/Operation analysis

* [Observations from the stellarparticle-campaign](https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/)
* [Ukraine Cyber Operations](https://github.com/curated-intel/Ukraine-Cyber-Operations/)
* [Browser In The Browser (BITB) Attack](https://mrd0x.com/browser-in-the-browser-phishing-attack/)
* [Russian State-Sponsored Cyber Actors Gain Network Access by Exploiting Default Multifactor Authentication Protocols and “PrintNightmare” Vulnerability #threatintel report](https://www.cisa.gov/uscert/ncas/alerts/aa22-074a)
* [Post auth RCE based in malicious LUA plugin script upload SCADA controllers located in Russia](https://medium.com/@bertinjoseb/post-auth-rce-based-in-malicious-lua-plugin-script-upload-scada-controllers-located-in-russia-57044425ac38)
* [Does This Look Infected? A Summary of APT41 Targeting U.S. State Governments](https://www.mandiant.com/resources/apt41-us-state-governments)

## Phishing

* [Revisiting Phishing Simulations](https://posts.specterops.io/revisiting-phishing-simulations-94d9cd460934)
* [Phishing page detection via learning classifiers from page layout feature](https://jwcn-eurasipjournals.springeropen.com/articles/10.1186/s13638-019-1361-0)
* [List of crowd-sourced phishing sites. Some are still active](https://phishtank.com)
* [mrd0x - phishing with spoofed cloud attachments](https://mrd0x.com/phishing-o365-spoofed-cloud-attachments/)
* [mrd0x - teams abuse](https://mrd0x.com/microsoft-teams-abuse/)
* [mrd0x - phishing with .ics](https://mrd0x.com/spoofing-calendar-invites-using-ics-files/)

## Active Directory

* [A comprehensive guide on relaying](https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/)
* [Automating a Red Team Lab (Part 1): Domain Creation](https://nickzero.co.uk/automating-a-red-team-lab/)
* [Automating a Red Team Lab (Part 2): Monitoring and Logging](https://nickzero.co.uk/automating-a-red-team-lab-part-2/)
* [Announcing Azure in BloodHound Enterprise](https://posts.specterops.io/announcing-azure-in-bloodhound-enterprise-b1a900557cda)
* [AD Trusts](https://medium.com/sse-blog/active-directory-spotlight-trusts-part-2-operational-guidance-ada54ac3bf13) 
* [Learn AD basics](https://www.udemy.com/course/active-directory/)

## Initial Access

* [How to Deliver Payloads in an Enterprise Attack with Steve Borosh](https://www.youtube.com/watch?v=vVueJfWmpGc)


## Persistence
* [SharpEventPersist](https://github.com/improsec/SharpEventPersist)
* [Persistence – Notepad++ Plugins](https://pentestlab.blog/2022/02/14/persistence-notepad-plugins/)

## OSINT

* [Nrich: Cli tool to quickly analyze all IPs in a file and see which ones have open ports/ vulnerabilities](https://gitlab.com/shodan-public/nrich)

## Workshops/Labs

* [Advanced-Process-Injection-Workshop by CyberWarFare Labs](https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop)
* [Detecting Adversarial Tradecrafts Tools by leveraging ETW](https://github.com/RedTeamOperations/Detecting-Adversarial-Tradecrafts-Tools-by-leveraging-ETW)
* [Data Only Attack: Neutralizing EtwTi Provider](https://public.cnotools.studio/bring-your-own-vulnerable-kernel-driver-byovkd/exploits/data-only-attack-neutralizing-etwti-provider)

## Tools

* [in memory lsass dumper using syscalls](https://github.com/helpsystems/nanodump)
* [Walter Planner: Attack path planner](https://jackson_t.gitlab.io/walter-planner/)
* [NimPackt-v1: A Nim-based packer for .NET executables and raw shellcode](https://github.com/chvancooten/NimPackt-v1)
* [PackMyPayload: Payload Containerization](https://github.com/mgeeky/PackMyPayload)
* [TymSpecial Shellcode Loader](https://github.com/ChadMotivation/TymSpecial)
* [KrbRelay](https://github.com/cube0x0/KrbRelay)
* [BadAssMacros: generate malicious macros](https://github.com/Inf0secRabbit/BadAssMacros)
* [PurplePanda: Identify privilege escalation paths and dangerous permissions](https://github.com/carlospolop/PurplePanda)
* [0d1n: a tool for automating customized attacks against web applications](https://github.com/CoolerVoid/0d1n)
* [Inceptor: a tool which can help to automate AV/EDR bypass](https://github.com/klezVirus/inceptor)
* [Injector: Complete Arsenal of Memory injection and other techniques for red-teaming in Windows](https://github.com/0xDivyanshu/Injector)
* [Pixload: Set of tools for creating/injecting payload into images](https://github.com/chinarulezzz/pixload)
* [Cloak: Generate python payloads via msfvenom and inject them into python scripts](https://github.com/s0md3v/Cloak)
* [SNOWCRASH: Create a scripts that can be launched on both Linux and Windows machines](https://github.com/redcode-labs/SNOWCRASH)

## Various contents
* [Running shellcode in electron](https://barbellsandrootshells.com/electron-shellcode-loader)
* [Cause & Effect…ive C2](https://www.ctus.io/2021/06/29/cause-effect-ive-c2/)
* [Eye of the TIBER - A blend of red team trends](https://www.youtube.com/watch?v=qyo6Rmy2odI)
* [Useful Libraries for Malware Development](https://captmeelo.com/redteam/maldev/2022/02/16/libraries-for-maldev.html)
* [Windows EVTX Samples [200 EVTX examples]](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
* [Russian Cyber Attack Escalation in Ukraine](https://www.youtube.com/watch?v=kO7LlnvE5Rs)
* [A Study on Blue Team’s OPSEC Failures](http://essay.utwente.nl/84945/1/__ad.utwente.nl_Org_BA_Bibliotheek_Documentfiles_Afstudeerverslagen__Verwerkt_caretta_crichlow_MA_eemcs.pdf)
* [Dive into the MITRE Engage™ Official Release](https://medium.com/mitre-engage/dive-into-the-mitre-engage-official-release-731504542924)
* [Conti leaked chats](https://github.com/tsale/translated_conti_leaked_comms)
* [Conti source code](https://github.com/Cracked5pider/conti_locker)
* [Attack Flow — Beyond Atomic Behaviors](https://medium.com/mitre-engenuity/attack-flow-beyond-atomic-behaviors-c646675cc793)
* [Offensive API Hooking](https://ilankalendarov.github.io/posts/offensive-hooking/)
* [VBA and Function Pointers](https://secureyourit.co.uk/wp/2020/11/28/vbafunctionpointers/)
* [MalAPI: List of Windows Apis classified by usage in malware dev](https://malapi.io)
* [Guest Diary (Etay Nir) Kernel Hooking Basics](https://isc.sans.edu/forums/diary/Guest+Diary+Etay+Nir+Kernel+Hooking+Basics/23155/)
* [BOF2shellcode — a tutorial converting a stand-alone BOF loader into shellcode](https://medium.com/falconforce/bof2shellcode-a-tutorial-converting-a-stand-alone-bof-loader-into-shellcode-6369aa518548)
* [Cobalt Strike User Defined Reflective Loader (UDRL)](https://github.com/kyleavery/TitanLdr/tree/heapencrypt)
* [DynamicWrapperEx – Windows API Invocation from Windows Script Host](https://www.contextis.com/en/blog/dynamicwrapperex-windows-api-invocation-from-windows-script-host?utm_source=linkedin&utm_medium=HootsuiteCTXIS&utm_campaign=649c522f-1883-4b51-8712-a299c4a9ac31)
* [Cracked5pider/ReflectedDll.c: Get output from injected reflected dll](https://gist.github.com/Cracked5pider/8f6196b4da16368318a75ff3b1836195)
* [Nt/Zw Mapping from Kernel32](https://github.com/EspressoCake/NativeFunctionStaticMap/blob/main/Native_API_Resolve.pdf)
* [DEF CON 29 - Ben Kurtz - Offensive Golang Bonanza: Writing Golang Malware](https://www.youtube.com/watch?v=3RQb05ITSyk)

## Azure related:

* [Cloud Adoption Framework for Azure Terraform landing zones](https://github.com/Azure/caf-terraform-landingzones)
* [March 2022 Update Release Notes: Cloud Adoption Framework for Azure Terraform landing zones](https://www.youtube.com/watch?v=B2CYOIAFt44)
* [Cloud Adoption Framework for Azure Terraform landing zones Documentation](https://aztfmod.github.io/documentation/)
* [Cloud Adoption Framework for Azure - Landing zones on Terraform - Rover](https://github.com/aztfmod/rover)


## C2 related:

* [Counter Strike 1.6 as Malware C2](https://www.youtube.com/watch?v=b2L1lWtwBiI&t=1s)
* [OffensiveNotion](https://github.com/mttaggart/OffensiveNotion)
* [We Put A C2 In Your Notetaking App: OffensiveNotion](https://medium.com/@huskyhacks.mk/we-put-a-c2-in-your-notetaking-app-offensivenotion-3e933bace332)
* [Building C2 implants in C++](https://shogunlab.gitbook.io/building-c2-implants-in-cpp-a-primer/)
* [C2 matrix - all your c2 needs here](https://docs.google.com/spreadsheets/d/1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc/edit#gid=0)

## Blue Team - how we get burnt

* [72-page eBook describing Endgame’s solution to hunting advanced cyberthreats](https://cyber-edge.com/resources/the-endgame-guide-to-threat-hunting/)
* [TiEtwAgent – ETW-based process injection detection (cant unhook from userland)](https://securityonline.info/tietwagent-etw-based-process-injection-detection/)
* [Detection Engineering](https://www.unh4ck.com/detection-engineering-dimensions)



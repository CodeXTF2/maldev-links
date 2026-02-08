#!/usr/bin/env python3
"""
Find Wayback Machine archives for broken links and update README.
"""

import re
import requests
import time

WAYBACK_API = "https://archive.org/wayback/available"

# Dead links from errors.txt
DEAD_LINKS = [
    ("Hooking via exceptions", "https://medium.com/@fsx30/vectored-exception-handling-hooking-via-forced-exception-f888754549c6"),
    ("Behind the Mask: Spoofing Call Stacks Dynamically with Timers", "https://www.cobaltstrike.com/blog/behind-the-mask-spoofing-call-stacks-dynamically-with-timers"),
    ("SysWhispers is dead, long live SysWhispers!", "https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/"),
    ("Bootlicker - UEFI rootkit", "https://github.com/realoriginal/bootlicker"),
    ("KnownDLLs injection", "https://www.codeproject.com/Articles/325603/Injection-into-a-Process-Using-KnownDlls"),
    ("Function hijacking", "https://klezvirus.github.io/RedTeaming/AV_Evasion/FromInjectionToHijacking/"),
    ("Massive guide on bypassing anticheat and antidebug - also works in malware against EDRs", "https://guidedhacking.com/forums/anticheat-bypass-antidebug-tutorials.46/"),
    ("Writing Beacon Object Files: Flexible, Stealthy, and Compatible: Direct syscalls from the real ntdll to bypas syscall detection", "https://www.cobaltstrike.com/blog/writing-beacon-object-files-flexible-stealthy-and-compatible/"),
    ("Post auth RCE based in malicious LUA plugin script upload SCADA controllers located in Russia", "https://medium.com/@bertinjoseb/post-auth-rce-based-in-malicious-lua-plugin-script-upload-scada-controllers-located-in-russia-57044425ac38"),
    ("AD Trusts", "https://medium.com/sse-blog/active-directory-spotlight-trusts-part-2-operational-guidance-ada54ac3bf13"),
    ("Learn AD basics", "https://www.udemy.com/course/active-directory/"),
    ("Kerberos Authentication Deep Dive", "https://medium.com/@harikrishnanp006/deep-dive-into-kerberos-authentication-6c124bac26fb"),
    ("NTLM and NTLMv2 Challenge-Response", "https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4"),
    ("Defeating Windows Defender Credential Guard", "https://research.ifcr.dk/pass-the-challenge-defeating-windows-defender-credential-guard-31a892eee22"),
    ("TymSpecial Shellcode Loader", "https://github.com/ChadMotivation/TymSpecial"),
    ("0d1n: a tool for automating customized attacks against web applications", "https://github.com/CoolerVoid/0d1n"),
    ("Injector: Complete Arsenal of Memory injection and other techniques for red-teaming in Windows", "https://github.com/0xDivyanshu/Injector"),
    ("Lord of the ring0", "https://idov31.github.io/2022/07/14/lord-of-the-ring0-p1.html"),
    ("Dive into the MITRE Engage™ Official Release", "https://medium.com/mitre-engage/dive-into-the-mitre-engage-official-release-731504542924"),
    ("Attack Flow — Beyond Atomic Behaviors", "https://medium.com/mitre-engenuity/attack-flow-beyond-atomic-behaviors-c646675cc793"),
    ("BOF2shellcode — a tutorial converting a stand-alone BOF loader into shellcode", "https://medium.com/falconforce/bof2shellcode-a-tutorial-converting-a-stand-alone-bof-loader-into-shellcode-6369aa518548"),
    ("VX-Underground Black Mass 2022", "https://papers.vx-underground.org/papers/Other/VXUG%20Zines/Black%20Mass%20Halloween%202022.pdf"),
    ("We Put A C2 In Your Notetaking App: OffensiveNotion", "https://medium.com/@huskyhacks.mk/we-put-a-c2-in-your-notetaking-app-offensivenotion-3e933bace332"),
    ("Playing in the Tradecraft Garden of Beacon", "https://www.cobaltstrike.com/blog/playing-in-the-tradecraft-garden-of-beacon"),
    # Error links (domain down)
    ("Kernel callbacks", "http://www.nynaeve.net/?p=200"),
    ("Data Only Attack: Neutralizing EtwTi Provider", "https://public.cnotools.studio/bring-your-own-vulnerable-kernel-driver-byovkd/exploits/data-only-attack-neutralizing-etwti-provider"),
    ("Running shellcode in electron", "https://barbellsandrootshells.com/electron-shellcode-loader"),
    ("VBA and Function Pointers", "https://secureyourit.co.uk/wp/2020/11/28/vbafunctionpointers/"),
]

def find_wayback_snapshot(url):
    """Find the most recent snapshot in Wayback Machine."""
    try:
        response = requests.get(WAYBACK_API, params={'url': url}, timeout=10)
        data = response.json()

        if 'archived_snapshots' in data and 'closest' in data['archived_snapshots']:
            snapshot = data['archived_snapshots']['closest']
            if snapshot.get('available'):
                return snapshot['url']
        return None
    except Exception as e:
        print(f"  Error checking Wayback: {e}")
        return None

def main():
    print("Searching Wayback Machine for archived copies...\n")
    print("="*80)

    replacements = []

    for title, url in DEAD_LINKS:
        print(f"\n[{title}]")
        print(f"Original: {url}")

        wayback_url = find_wayback_snapshot(url)

        if wayback_url:
            print(f"[+] Found:  {wayback_url}")
            replacements.append((url, wayback_url))
        else:
            print(f"[-] No archive found")

        time.sleep(1)  # Be nice to Wayback Machine

    # Print summary
    print("\n" + "="*80)
    print(f"SUMMARY: Found {len(replacements)} archived copies")
    print("="*80)

    if replacements:
        print("\nUpdating README.md...")

        with open('README.md', 'r', encoding='utf-8') as f:
            content = f.read()

        for old_url, new_url in replacements:
            # Escape special regex characters
            old_url_escaped = re.escape(old_url)
            content = re.sub(old_url_escaped, new_url, content)
            print(f"  Replaced: {old_url[:60]}...")

        with open('README.md', 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"\n[+] Updated {len(replacements)} links in README.md")
    else:
        print("\nNo replacements to make.")

if __name__ == '__main__':
    main()


"""
Check all links in a markdown file for dead links and redirects.
"""

import re
import requests
from urllib.parse import urlparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
TIMEOUT = 10  # seconds
MAX_WORKERS = 10  # concurrent requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

def extract_links(md_file):
    """Extract all URLs from markdown file."""
    with open(md_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Match markdown links: [text](url)
    pattern = r'\[([^\]]+)\]\(([^\)]+)\)'
    matches = re.findall(pattern, content)

    return [(title, url) for title, url in matches if url.startswith('http')]

def check_link(title, url):
    """Check if a link is dead or redirected."""
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={'User-Agent': USER_AGENT}
        )

        status = response.status_code
        final_url = response.url

        # Check if redirected
        if final_url != url:
            # Check if it's just http->https or trailing slash
            original_parsed = urlparse(url)
            final_parsed = urlparse(final_url)

            # Significant redirect if domain changed or path changed significantly
            url_normalized = url.rstrip('/').replace('http://', 'https://')
            final_normalized = final_url.rstrip('/').replace('http://', 'https://')

            if url_normalized != final_normalized:
                return {
                    'title': title,
                    'url': url,
                    'status': 'redirected',
                    'status_code': status,
                    'redirect_url': final_url
                }

        # Check status code
        if status >= 400:
            return {
                'title': title,
                'url': url,
                'status': 'dead',
                'status_code': status
            }

        return {
            'title': title,
            'url': url,
            'status': 'ok',
            'status_code': status
        }

    except requests.exceptions.Timeout:
        return {
            'title': title,
            'url': url,
            'status': 'timeout',
            'error': 'Request timed out'
        }
    except requests.exceptions.TooManyRedirects:
        return {
            'title': title,
            'url': url,
            'status': 'error',
            'error': 'Too many redirects'
        }
    except requests.exceptions.RequestException as e:
        return {
            'title': title,
            'url': url,
            'status': 'error',
            'error': str(e)
        }

def main():
    md_file = 'README.md'

    print(f"Extracting links from {md_file}...")
    links = extract_links(md_file)
    print(f"Found {len(links)} links to check\n")

    results = {
        'ok': [],
        'dead': [],
        'redirected': [],
        'timeout': [],
        'error': []
    }

    # Check links concurrently
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_link, title, url): (title, url)
                   for title, url in links}

        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results[result['status']].append(result)

            # Progress indicator
            status_symbol = {
                'ok': '[+]',
                'dead': '[-]',
                'redirected': '[~]',
                'timeout': '[?]',
                'error': '[!]'
            }
            print(f"[{i}/{len(links)}] {status_symbol[result['status']]} {result['title'][:60]}")

            # Small delay to avoid overwhelming servers
            time.sleep(0.1)

    # Update README with dead link tags
    print("\nUpdating README.md with tags...")
    with open(md_file, 'r', encoding='utf-8') as f:
        content = f.read()

    dead_count = 0
    redirect_count = 0

    # Tag dead links
    for r in results['dead']:
        # Create the markdown link pattern - need to match exactly as it appears
        link_text = f"[{r['title']}]({r['url']})"
        # Check if tag is already present
        if link_text in content and '💀 DEAD LINK!' not in content[content.find(link_text):content.find(link_text)+len(link_text)+30]:
            replacement = f"[{r['title']}]({r['url']}) 💀 DEAD LINK!"
            content = content.replace(link_text, replacement, 1)
            dead_count += 1

    # Also tag timeout and error links as dead
    for r in results['timeout'] + results['error']:
        link_text = f"[{r['title']}]({r['url']})"
        if link_text in content and '💀 DEAD LINK!' not in content[content.find(link_text):content.find(link_text)+len(link_text)+30]:
            replacement = f"[{r['title']}]({r['url']}) 💀 DEAD LINK!"
            content = content.replace(link_text, replacement, 1)
            dead_count += 1

    # Tag redirected links
    for r in results['redirected']:
        link_text = f"[{r['title']}]({r['url']})"
        # Check if tag is already present
        if link_text in content and '⚠️ REDIRECTED!' not in content[content.find(link_text):content.find(link_text)+len(link_text)+30]:
            replacement = f"[{r['title']}]({r['url']}) ⚠️ REDIRECTED!"
            content = content.replace(link_text, replacement, 1)
            redirect_count += 1

    if dead_count > 0 or redirect_count > 0:
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(content)
        if dead_count > 0:
            print(f"Added 💀 DEAD LINK! tag to {dead_count} links")
        if redirect_count > 0:
            print(f"Added ⚠️ REDIRECTED! tag to {redirect_count} links")
        print()

    # Print summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"[+] OK: {len(results['ok'])}")
    print(f"[-] Dead: {len(results['dead'])}")
    print(f"[~] Redirected: {len(results['redirected'])}")
    print(f"[?] Timeout: {len(results['timeout'])}")
    print(f"[!] Error: {len(results['error'])}")

    # Print dead links
    if results['dead']:
        print("\n" + "="*80)
        print("DEAD LINKS")
        print("="*80)
        for r in results['dead']:
            print(f"\n[{r['title']}]")
            print(f"  URL: {r['url']}")
            print(f"  Status: {r['status_code']}")

    # Print redirected links
    if results['redirected']:
        print("\n" + "="*80)
        print("REDIRECTED LINKS")
        print("="*80)
        for r in results['redirected']:
            print(f"\n[{r['title']}]")
            print(f"  Original:  {r['url']}")
            print(f"  Redirect:  {r['redirect_url']}")
            print(f"  Status: {r['status_code']}")

    # Print timeout links
    if results['timeout']:
        print("\n" + "="*80)
        print("TIMEOUT LINKS")
        print("="*80)
        for r in results['timeout']:
            print(f"\n[{r['title']}]")
            print(f"  URL: {r['url']}")

    # Print error links
    if results['error']:
        print("\n" + "="*80)
        print("ERROR LINKS")
        print("="*80)
        for r in results['error']:
            print(f"\n[{r['title']}]")
            print(f"  URL: {r['url']}")
            print(f"  Error: {r['error']}")

if __name__ == '__main__':
    main()

#!/usr/bin/env python3

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
import urllib3

# Optional colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    GREEN, RED, YELLOW, CYAN = Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.CYAN
    RESET, BOLD = Style.RESET_ALL, Style.BRIGHT
except ImportError:
    GREEN = RED = YELLOW = CYAN = RESET = BOLD = ""

# Banner
BANNER = f"""{CYAN}{BOLD}
   (✿◠‿◠)   Anime RSC Scanner   (◠‿◠✿)

   ╔══════════════════════════════════════╗
        CVE‑2025‑55182 Surface Detector
        React Server Components Exposure
        Styled in Anime Spirit ✦
        by Spycio.Kon
   ╚══════════════════════════════════════╝
{RESET}"""


def get_args():
    parser = argparse.ArgumentParser(description="Scan for CVE-2025-55182 (React RSC) surface exposure.")

    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-u", "--url", help="Single target URL (e.g., http://localhost:3000)")
    grp.add_argument("-l", "--list", help="File containing list of URLs to scan")

    parser.add_argument("-o", "--output", help="Save results to a file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable TLS verification")

    return parser.parse_args()


def normalize_url(url: str) -> str:
    if not url.startswith("http"):
        url = f"http://{url}"
    return url.rstrip("/")


def check_target(url, timeout, verbose, verify_tls):
    target = normalize_url(url)

    headers = {
        "User-Agent": "Mozilla/5.0 (Security-Audit; CVE-2025-55182-Scanner)",
        "Accept": "text/x-component",
        "Content-Type": "text/plain;charset=UTF-8",
        "Next-Action": "non_existent_action_id",
        "RSC": "1",
    }

    payload = "[]"

    try:
        if verbose:
            print(f"[*] Probing {target}...")

        res = requests.post(
            target,
            headers=headers,
            data=payload,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=True,
        )

        ct = res.headers.get("Content-Type", "")
        powered = res.headers.get("X-Powered-By", "")

        exposed = False

        if "text/x-component" in ct:
            exposed = True
            msg = f"{RED}[EXPOSED]{RESET} Server speaks RSC. Patch verification required."
        elif res.status_code == 500 and "Next" in powered:
            exposed = True
            msg = f"{YELLOW}[WARNING]{RESET} Server crashed on RSC payload. Potential exposure."
        elif res.status_code == 404:
            msg = f"{GREEN}[SAFE]{RESET} Endpoint not found."
        else:
            msg = f"{GREEN}[SAFE]{RESET} HTTP {res.status_code} - No RSC signature detected."

        return {"url": target, "status": res.status_code, "rsc_exposed": exposed, "msg": msg}

    except requests.exceptions.RequestException as e:
        return {"url": target, "status": "ERR", "rsc_exposed": False,
                "msg": f"{CYAN}[ERROR]{RESET} Connection failed: {e}"}


def main():
    print(BANNER)
    args = get_args()

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.url:
        targets = [args.url]
    else:
        try:
            with open(args.list) as f:
                targets = [x.strip() for x in f if x.strip()]
        except FileNotFoundError:
            print(f"{RED}[!] File not found: {args.list}{RESET}")
            sys.exit(1)

    print(f"[*] Loaded {len(targets)} target(s). Starting scan...\n")

    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(check_target, t, args.timeout, args.verbose, not args.insecure)
                   for t in targets]

        for fut in futures:
            r = fut.result()
            results.append(r)
            print(f"Target: {r['url']:<30} | Status: {r['status']:<4} | {r['msg']}")

    if args.output:
        with open(args.output, "w") as f:
            for r in results:
                clean = r["msg"].replace(RED, "").replace(GREEN, "").replace(YELLOW, "").replace(CYAN, "").replace(RESET, "")
                f.write(f"{r['url']}, {r['status']}, {clean}\n")
        print(f"\n{BOLD}[*] Results saved to {args.output}{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan interrupted by user.{RESET}")
        sys.exit(0)

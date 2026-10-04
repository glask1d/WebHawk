#!/usr/bin/env python3
"""
crt-scout - Fast subdomain discovery + live checking + wordlist generation

Usage: python crt-scout.py <domain> [options]
"""

import argparse
import asyncio
import sys
import re
import ssl
from typing import Set, List, Tuple, Optional

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def color(text: str, color_code: str) -> str:
    return f"{color_code}{text}{Colors.RESET}"


class CrtScout:
    API_URL = "https://crt.name/v1/search"
    
    def __init__(self, domain: str, args):
        self.domain = domain
        self.args = args
        self.subdomains: Set[str] = set()
        self.results: List[Tuple[str, str, Optional[int]]] = []
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def fetch_subdomains(self) -> Set[str]:
        """Query crt.name API for subdomains."""
        import aiohttp

        print(color(f"[*] Querying crt.name for {self.domain} ...", Colors.BLUE), file=sys.stderr)
        
        params = {"apex": self.domain}
        if self.args.dates:
            params["dates"] = "1"
            
        headers = {"User-Agent": self.args.ua}
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(self.API_URL, params=params, ssl=self.ssl_context) as resp:
                    if resp.status != 200:
                        print(color(f"[!] API returned status {resp.status}", Colors.RED), file=sys.stderr)
                        return set()
                    
                    text = await resp.text()
                    
        except asyncio.TimeoutError:
            print(color("[!] Request timed out", Colors.RED), file=sys.stderr)
            return set()
        except Exception as e:
            print(color(f"[!] Request failed: {e}", Colors.RED), file=sys.stderr)
            return set()
        
        # Parse response - each line is "subdomain [date]"
        for line in text.strip().split("\n"):
            if line.strip():
                subdomain = line.split()[0]
                self.subdomains.add(subdomain.lower())
                
        if not self.subdomains:
            print(color("[!] No subdomains returned", Colors.RED), file=sys.stderr)
            return set()
            
        print(color(f"[+] Found {len(self.subdomains)} unique subdomains", Colors.GREEN), file=sys.stderr)
        return self.subdomains
    
    def generate_wordlist(self) -> Set[str]:
        """Extract unique subdomain prefixes."""
        if not self.args.wordlist:
            return set()
            
        print(color("[*] Building wordlist of subdomain prefixes ...", Colors.BLUE), file=sys.stderr)
        
        words = set()
        escaped_domain = re.escape(self.domain)
        
        for subdomain in self.subdomains:
            # Remove domain suffix
            prefix = re.sub(rf"\.?{escaped_domain}$", "", subdomain)
            if prefix:
                # Split on dots and add each part
                for part in prefix.split("."):
                    if part and part not in ("www", "mail", "ftp", "blog", "shop"):
                        words.add(part)
                        
        # Save wordlist
        try:
            with open(self.args.wordlist, "w") as f:
                for word in sorted(words):
                    f.write(f"{word}\n")
            print(color(f"[+] Saved {len(words)} unique prefixes to {self.args.wordlist}", Colors.GREEN), file=sys.stderr)
        except IOError as e:
            print(color(f"[!] Failed to save wordlist: {e}", Colors.RED), file=sys.stderr)
            
        return words
    
    async def check_host(self, host: str, session, semaphore: asyncio.Semaphore) -> Tuple[str, str, Optional[int]]:
        """Check if a host is alive via HTTP/HTTPS."""
        import aiohttp

        schemes = ["https"] if self.args.https_only else ["https", "http"]
        
        async with semaphore:
            for scheme in schemes:
                url = f"{scheme}://{host}"
                try:
                    async with session.get(
                        url, 
                        ssl=self.ssl_context,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=self.args.timeout + 3)
                    ) as resp:
                        status = resp.status
                        if status:
                            return (host, scheme, status)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
                except Exception:
                    continue
                    
        return (host, "dead", None)
    
    async def check_all_hosts(self):
        """Check all subdomains concurrently."""
        if not self.subdomains:
            return
            
        import aiohttp

        print(color(f"[*] Checking {len(self.subdomains)} subdomains (timeout={self.args.timeout}s, workers={self.args.workers}) ...", Colors.BLUE), file=sys.stderr)
        print(file=sys.stderr)
        
        semaphore = asyncio.Semaphore(self.args.workers)
        headers = {"User-Agent": self.args.ua}
        
        timeout = aiohttp.ClientTimeout(connect=self.args.timeout)
        
        async with aiohttp.ClientSession(
            timeout=timeout, 
            headers=headers,
            connector=aiohttp.TCPConnector(limit=100, ssl=self.ssl_context)
        ) as session:
            
            tasks = [
                self.check_host(subdomain, session, semaphore) 
                for subdomain in sorted(self.subdomains)
            ]
            
            # Progress bar
            completed = 0
            for coro in asyncio.as_completed(tasks):
                result = await coro
                self.results.append(result)
                completed += 1
                
                if not self.args.quiet:
                    print(f"\r[*] Progress: {completed}/{len(tasks)}", end="", file=sys.stderr)
                    
        if not self.args.quiet:
            print(file=sys.stderr)
    
    def print_results(self):
        """Display or save results."""
        if not self.results:
            # Just print subdomains
            for subdomain in sorted(self.subdomains):
                print(subdomain)
            return
            
        # Sort results: live first, then by status code
        live_results = [r for r in self.results if r[1] != "dead"]
        dead_results = [r for r in self.results if r[1] == "dead"]
        
        live_results.sort(key=lambda x: (x[1], x[2] or 0))
        
        output_lines = []
        
        for host, scheme, status in live_results:
            line = f"[LIVE] {scheme}://{host}  →  HTTP {status}"
            output_lines.append(line)
            if not self.args.output:
                print(color(line, Colors.GREEN))
                
        if self.args.show_dead:
            for host, scheme, status in dead_results:
                line = f"[DEAD] {host}"
                output_lines.append(line)
                if not self.args.output:
                    print(color(line, Colors.RED))
                    
        # Save to file
        if self.args.output:
            try:
                with open(self.args.output, "w") as f:
                    for line in output_lines:
                        f.write(f"{line}\n")
                        
                print(color(f"\n[+] Full results saved to: {self.args.output}", Colors.GREEN), file=sys.stderr)
                print(color(f"[+] Live hosts: {len(live_results)}", Colors.GREEN), file=sys.stderr)
                
                if live_results:
                    print(color("\nLive URLs:", Colors.CYAN), file=sys.stderr)
                    for host, scheme, status in live_results[:20]:
                        print(f"  {scheme}://{host} ({status})", file=sys.stderr)
                    if len(live_results) > 20:
                        print(f"  ... and {len(live_results) - 20} more", file=sys.stderr)
                        
            except IOError as e:
                print(color(f"[!] Failed to save output: {e}", Colors.RED), file=sys.stderr)

    async def run(self):
        """Main execution flow."""
        await self.fetch_subdomains()
        
        if not self.subdomains:
            return
            
        self.generate_wordlist()
        
        if self.args.check:
            await self.check_all_hosts()
            
        self.print_results()


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fast subdomain discovery + live checking + wordlist generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python crt-scout.py x.com
  python crt-scout.py x.com -w words.txt
  python crt-scout.py x.com --check -o live.txt -w words.txt
  python crt-scout.py x.com -c --workers 50
        """
    )
    
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-c", "--check", action="store_true", 
                       help="Check which subdomains are alive")
    parser.add_argument("--https-only", action="store_true",
                       help="Only probe HTTPS (skip HTTP)")
    parser.add_argument("--ua", dest="ua", 
                       default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                       help="Custom User-Agent")
    parser.add_argument("-o", "--output", 
                       help="Save results to a file")
    parser.add_argument("-w", "--wordlist", 
                       help="Extract unique subdomain prefixes to wordlist")
    parser.add_argument("-d", "--dates", action="store_true",
                       help="Include first-seen dates in API query")
    parser.add_argument("--timeout", type=int, default=5,
                       help="Connection timeout in seconds (default: 5)")
    parser.add_argument("--workers", type=int, default=50,
                       help="Concurrent workers for checking (default: 50)")
    parser.add_argument("--show-dead", action="store_true",
                       help="Include dead hosts in output")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Suppress progress output")
    
    return parser


async def main():
    parser = create_parser()
    args = parser.parse_args()
    
    # Validate domain format
    if not re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$", args.domain):
        print(color(f"[!] Invalid domain format: {args.domain}", Colors.RED), file=sys.stderr)
        sys.exit(1)
    
    scout = CrtScout(args.domain, args)
    await scout.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(color("\n[!] Interrupted by user", Colors.YELLOW), file=sys.stderr)
        sys.exit(130)

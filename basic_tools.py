# CELL 3: Subdomain enumeration
import requests
from rich.console import Console
from rich.panel import Panel
console = Console()
a
def subdomains_via_subfinder(domain):
    """Method 1: subfinder (passive)"""
    try:
        r = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=180
        )
        return set(r.stdout.strip().split("\n")) - {""}
    except Exception as e:
        print(f"subfinder error: {e}")
        return set()

def subdomains_via_crtsh(domain):
    """Method 2: crt.sh (certificate transparency)"""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30
        )
        data = r.json()
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(domain):
                    subs.add(name)
        return subs
    except Exception as e:
        print(f"crt.sh error: {e}")
        return set()

def subdomains_via_bruteforce(domain, wordlist=None):
    """Method 3: DNS brute-force with common subdomains"""
    if wordlist is None:
        wordlist = [
            "www","mail","ftp","localhost","webmail","smtp","pop","ns1","webdisk",
            "ns2","cpanel","whm","autodiscover","autoconfig","m","imap","test",
            "ns","blog","pop3","dev","www2","admin","forum","news","vpn","ns3",
            "mail2","new","mysql","old","lists","support","mobile","mx","static",
            "docs","beta","shop","sql","secure","demo","cp","calendar","wiki",
            "web","media","email","images","img","download","dns","api","staging",
            "portal","app","git","gitlab","jenkins","ci","cd","prod","stage",
        ]
    import dns.resolver
    found = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            resolver.resolve(fqdn, "A")
            found.add(fqdn)
        except:
            pass
    return found

def find_subdomains(domain):
    console.print(Panel(f"🔎 Finding subdomains for [bold]{domain}[/bold]", style="cyan"))

    all_subs = set()

    console.print("[yellow]→ Method 1: subfinder[/yellow]")
    subs1 = subdomains_via_subfinder(domain)
    console.print(f"   found: {len(subs1)}")
    all_subs |= subs1

    console.print("[yellow]→ Method 2: crt.sh[/yellow]")
    subs2 = subdomains_via_crtsh(domain)
    console.print(f"   found: {len(subs2)}")
    all_subs |= subs2

    console.print("[yellow]→ Method 3: brute-force[/yellow]")
    subs3 = subdomains_via_bruteforce(domain)
    console.print(f"   found: {len(subs3)}")
    all_subs |= subs3

    result = sorted(all_subs)
    console.print(f"\n[green]✅ Total unique subdomains: {len(result)}[/green]")
    return result

def check_live_hosts(subdomains):
    """Filter live hosts using httpx"""
    if not subdomains:
        return []
    try:
        with open("/tmp/subs.txt", "w") as f:
            f.write("\n".join(subdomains))
        r = subprocess.run(
            ["httpx", "-l", "/tmp/subs.txt", "-silent", "-status-code", "-title", "-tech-detect"],
            capture_output=True, text=True, timeout=300
        )
        return r.stdout.strip().split("\n")
    except Exception as e:
        print(f"httpx error: {e}")
        return []

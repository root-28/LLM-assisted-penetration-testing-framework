# CELL 6: Tech stack detection (Wappalyzer-style)

import re

# Simplified fingerprint DB 
TECH_SIGNATURES = {
    "WordPress":   {"headers": [], "body": [r"wp-content", r"wp-includes"], "cookies": ["wordpress_"]},
    "Drupal":      {"headers": ["X-Generator: Drupal"], "body": [r"sites/default/files"], "cookies": []},
    "Joomla":      {"headers": [], "body": [r"/components/com_", r"joomla"], "cookies": []},
    "React":       {"headers": [], "body": [r"react", r"_reactRootContainer"], "cookies": []},
    "Next.js":     {"headers": ["X-Powered-By: Next.js"], "body": [r"__NEXT_DATA__"], "cookies": []},
    "Vue.js":      {"headers": [], "body": [r"vue\.js", r"v-app"], "cookies": []},
    "Angular":     {"headers": [], "body": [r"ng-version", r"angular"], "cookies": []},
    "jQuery":      {"headers": [], "body": [r"jquery"], "cookies": []},
    "Bootstrap":   {"headers": [], "body": [r"bootstrap"], "cookies": []},
    "Nginx":       {"headers": ["Server: nginx"], "body": [], "cookies": []},
    "Apache":      {"headers": ["Server: Apache"], "body": [], "cookies": []},
    "IIS":         {"headers": ["Server: Microsoft-IIS"], "body": [], "cookies": []},
    "Cloudflare":  {"headers": ["Server: cloudflare", "CF-RAY"], "body": [], "cookies": ["__cfduid", "cf_clearance"]},
    "PHP":         {"headers": ["X-Powered-By: PHP"], "body": [], "cookies": ["PHPSESSID"]},
    "ASP.NET":     {"headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version"], "body": [], "cookies": ["ASP.NET_SessionId"]},
    "Django":      {"headers": [], "body": [], "cookies": ["csrftoken", "sessionid"]},
    "Flask":       {"headers": ["Server: Werkzeug"], "body": [], "cookies": ["session"]},
    "Express":     {"headers": ["X-Powered-By: Express"], "body": [], "cookies": []},
    "Laravel":     {"headers": [], "body": [], "cookies": ["laravel_session", "XSRF-TOKEN"]},
    "Google Analytics": {"headers": [], "body": [r"google-analytics\.com", r"gtag\("], "cookies": ["_ga", "_gid"]},
    "Google Tag Manager": {"headers": [], "body": [r"googletagmanager\.com"], "cookies": []},
    "Stripe":      {"headers": [], "body": [r"js\.stripe\.com"], "cookies": []},
    "HubSpot":     {"headers": [], "body": [r"hs-scripts\.com", r"hubspot"], "cookies": []},
    "Shopify":     {"headers": ["X-ShopId", "X-Shopify-Stage"], "body": [r"cdn\.shopify\.com"], "cookies": ["_shopify_"]},
    "Wix":         {"headers": ["X-Wix-Request-Id"], "body": [r"static\.wixstatic\.com"], "cookies": []},
    "Squarespace": {"headers": [], "body": [r"static1\.squarespace\.com"], "cookies": []},
}

def detect_tech(url):
    """Wappalyzer-style detection"""
    console.print(f"🔬 Detecting tech: [cyan]{url}[/cyan]")
    try:
        r = requests.get(url, timeout=15, verify=False, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0"})
    except Exception as e:
        return {"url": url, "error": str(e), "technologies": []}

    headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body = r.text[:200000]
    cookies = "; ".join(r.cookies.keys())

    detected = []
    for tech, sigs in TECH_SIGNATURES.items():
        found = False
        # Headers
        for h in sigs.get("headers", []):
            if h.lower() in headers_text.lower():
                found = True; break
        # Body
        if not found:
            for b in sigs.get("body", []):
                if re.search(b, body, re.I):
                    found = True; break
        # Cookies
        if not found:
            for c in sigs.get("cookies", []):
                if c.lower() in cookies.lower():
                    found = True; break
        if found:
            detected.append(tech)

    # Extra: extract meta generator, server header
    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")
    gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', body, re.I)
    generator = gen_match.group(1) if gen_match else ""

    result = {
        "url": url,
        "status": r.status_code,
        "server": server,
        "powered_by": powered,
        "generator": generator,
        "technologies": sorted(set(detected)),
    }

    console.print(f"  [green]Found:[/green] {', '.join(result['technologies']) or 'none'}")
    if server: console.print(f"  [dim]Server: {server}[/dim]")
    return result

# CELL 4: WHOIS
import whois
from datetime import datetime

def whois_lookup(domain):
    console.print(Panel(f"📋 WHOIS for [bold]{domain}[/bold]", style="cyan"))
    try:
        w = whois.whois(domain)
        info = {
            "domain_name":  w.domain_name,
            "registrar":    w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers,
            "status":       w.status,
            "emails":       w.emails,
            "org":          w.org,
            "country":      w.country,
        }
        # Pretty print
        for k, v in info.items():
            if v:
                console.print(f"  [bold]{k}:[/bold] {v}")

        # Extra: age calculation
        if w.creation_date:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age_days = (datetime.now() - cd).days
            console.print(f"  [bold]domain_age:[/bold] {age_days} days")

        return info
    except Exception as e:
        console.print(f"[red]❌ WHOIS error: {e}[/red]")
        return {}

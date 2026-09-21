# CELL 7: Full recon pipeline

from datetime import datetime
import json

def full_recon(domain, do_tcp=True, do_udp=False, do_service=True,
               use_llm=True, save_report=True):
    """Full recon workflow"""
    started = datetime.now()
    console.print(Panel(
        f"[bold green]🎯 FULL RECON[/bold green]\n"
        f"Target: [cyan]{domain}[/cyan]\n"
        f"Started: {started:%Y-%m-%d %H:%M:%S}",
        style="green"
    ))

    report = {"target": domain, "started": str(started)}

    # ---- 1. Subdomains ----
    subs = find_subdomains(domain)
    report["subdomains"] = subs

    # ---- 2. Live hosts ----
    console.print("\n[yellow]→ Checking live hosts (httpx)[/yellow]")
    live = check_live_hosts(subs[:100])   # limit
    report["live_hosts"] = [l for l in live if l.strip()]
    console.print(f"  [green]Live:[/green] {len(report['live_hosts'])}")

    # ---- 3. WHOIS ----
    report["whois"] = whois_lookup(domain)

    # ---- 4. Port scan on apex domain ----
    import socket
    try:
        ip = socket.gethostbyname(domain)
        report["ip"] = ip
        console.print(f"\n[cyan]Resolved {domain} → {ip}[/cyan]")
    except:
        ip = domain
        report["ip"] = None

    if do_tcp:
        tcp_out = tcp_scan(ip, ports="1-1000")
        report["tcp_scan_raw"] = tcp_out
        report["tcp_open"] = parse_nmap_xml(tcp_out)

    if do_udp:
        udp_out = udp_scan(ip)
        report["udp_scan_raw"] = udp_out
        report["udp_open"] = parse_nmap_xml(udp_out)

    if do_service:
        svc_out = service_scan(ip, ports="1-1000")
        report["service_scan_raw"] = svc_out

    # ---- 5. Tech detection on live hosts ----
    console.print("\n[yellow]→ Tech detection[/yellow]")
    tech_results = []
    for lh in report["live_hosts"][:10]:   # top 10
        url = lh.split()[0]
        if not url.startswith("http"):
            url = "https://" + url
        tech_results.append(detect_tech(url))
    report["technologies"] = tech_results

    # ---- 6. LLM analysis ----
    if use_llm:
        console.print("\n[magenta]🧠 AI Analysis...[/magenta]")
        summary_input = json.dumps({
            "target": domain,
            "subdomains_count": len(subs),
            "sample_subdomains": subs[:30],
            "live_hosts": report["live_hosts"][:20],
            "whois": {k:v for k,v in report["whois"].items() if v},
            "open_ports": report.get("tcp_open", {}),
            "technologies": [
                {"url": t.get("url"), "techs": t.get("technologies", [])}
                for t in tech_results
            ],
        }, indent=2, default=str)

        report["ai_analysis"] = analyze_with_llm(summary_input, title=f"Recon Summary: {domain}")
        console.print(Panel(report["ai_analysis"], title="🧠 AI Analysis", style="magenta"))

    # ---- 7. Save ----
    if save_report:
        fname = f"{WORKDIR}/recon_{domain}_{started:%Y%m%d_%H%M}.json"
        with open(fname, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"\n[green]💾 Saved:[/green] {fname}")

    console.print(f"\n[bold green]✅ Done in {(datetime.now()-started).seconds}s[/bold green]")
    return report

print("✅ full_recon() ready")

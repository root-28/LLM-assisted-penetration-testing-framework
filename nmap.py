# CELL 5: Port scanning with nmap

def tcp_scan(target, ports="1-1000", timing="T4", extra=None):
    """TCP SYN scan"""
    console.print(Panel(f"🔌 TCP Scan: [bold]{target}[/bold] ports={ports}", style="cyan"))
    cmd = ["nmap", "-sS", "-Pn", f"-{timing}", "-p", ports, "--open", "-oX", "-", target]
    if extra:
        cmd = cmd[:1] + extra + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        return r.stdout
    except subprocess.TimeoutExpired:
        return "⏱️ TCP scan timeout"
    except Exception as e:
        return f"❌ {e}"

def udp_scan(target, ports="53,67,68,69,123,137,138,139,161,162,445,500,514,520,631,1900,4500,5353"):
    """Top UDP ports scan (slow!)"""
    console.print(Panel(f"📡 UDP Scan: [bold]{target}[/bold] (top ports)", style="cyan"))
    cmd = ["nmap", "-sU", "-Pn", "--top-ports", "50", "--open", "-oX", "-", target]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        return r.stdout
    except subprocess.TimeoutExpired:
        return "⏱️ UDP scan timeout"
    except Exception as e:
        return f"❌ {e}"

def service_scan(target, ports="1-1000"):
    """Service + version detection"""
    console.print(Panel(f"🔬 Service Detection: [bold]{target}[/bold]", style="cyan"))
    cmd = ["nmap", "-sV", "-sC", "-Pn", "-p", ports, "--open", "-oX", "-", target]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        return r.stdout
    except Exception as e:
        return f"❌ {e}"

def parse_nmap_xml(xml_text):
    """Nmap XML → structured dict"""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except:
        return {}

    results = {}
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None: continue
        ip = addr_el.get("addr")
        ports = []
        for port in host.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports.append({
                "port": port.get("portid"),
                "proto": port.get("protocol"),
                "service": service.get("name") if service is not None else "",
                "version": f"{service.get('product','')} {service.get('version','')}".strip() if service is not None else "",
            })
        results[ip] = ports
    return results

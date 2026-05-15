import os
import json
import re
import socket
import httpx
from datetime import datetime

SHODAN_KEY  = os.getenv("SHODAN_API_KEY",    "")
VT_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
HUNTER_KEY  = os.getenv("HUNTER_API_KEY",    "")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY",   "")

_HEADERS = {"User-Agent": "CyberKB-OSINT/3.0"}


# ══════════════════════════════════════════════════════════
#  DOMINIO
# ══════════════════════════════════════════════════════════

async def whois_lookup(domain: str) -> dict:
    try:
        import whois
        data = whois.whois(domain)
        return {
            "domain":          domain,
            "registrar":       str(data.registrar or ""),
            "creation_date":   str(data.creation_date or ""),
            "expiration_date": str(data.expiration_date or ""),
            "name_servers":    list(data.name_servers or []),
            "emails":          list(data.emails if isinstance(data.emails, list) else ([data.emails] if data.emails else [])),
            "org":             str(data.org or ""),
            "country":         str(data.country or ""),
            "status":          list(data.status if isinstance(data.status, list) else ([data.status] if data.status else [])),
        }
    except Exception as e:
        return {"error": str(e)}


async def dns_lookup(domain: str) -> dict:
    try:
        import dns.resolver
        result = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                result[rtype] = [str(r) for r in answers]
            except Exception:
                result[rtype] = []
        return {"domain": domain, "records": result}
    except Exception as e:
        return {"error": str(e)}


async def subdomains_crtsh(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=20, headers=_HEADERS) as client:
            r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            entries = r.json()
        subs = set()
        for e in entries:
            name = e.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    subs.add(sub)
        return {"domain": domain, "subdomains": sorted(subs), "count": len(subs)}
    except Exception as e:
        return {"error": str(e)}


async def ssl_cert(domain: str) -> dict:
    """SSL certificate info from crt.sh + live TLS handshake."""
    try:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        results = {}
        try:
            conn = ctx.wrap_socket(socket.create_connection((domain, 443), timeout=8), server_hostname=domain)
            cert = conn.getpeercert()
            conn.close()
            results["subject"]     = dict(x[0] for x in cert.get("subject", []))
            results["issuer"]      = dict(x[0] for x in cert.get("issuer", []))
            results["not_before"]  = cert.get("notBefore", "")
            results["not_after"]   = cert.get("notAfter", "")
            results["san"]         = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            results["version"]     = cert.get("version", "")
            results["serial"]      = str(cert.get("serialNumber", ""))
        except Exception as e:
            results["tls_error"] = str(e)

        # Also fetch recent certs from crt.sh
        async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
            r = await client.get(f"https://crt.sh/?q={domain}&output=json")
            if r.status_code == 200:
                certs = r.json()[:10]
                results["recent_certs"] = [
                    {
                        "id":          c.get("id"),
                        "logged_at":   c.get("entry_timestamp", "")[:10],
                        "not_before":  c.get("not_before", "")[:10],
                        "not_after":   c.get("not_after", "")[:10],
                        "issuer":      c.get("issuer_name", ""),
                        "name":        c.get("name_value", ""),
                    }
                    for c in certs
                ]
        results["domain"] = domain
        return results
    except Exception as e:
        return {"error": str(e)}


async def wayback(url: str) -> dict:
    """Check Wayback Machine snapshots (CDX API — no auth needed)."""
    try:
        # Normalise: strip protocol for CDX if needed
        query_url = url if url.startswith("http") else f"http://{url}"
        async with httpx.AsyncClient(timeout=20, headers=_HEADERS) as client:
            # CDX summary
            cdx_url = (
                "https://web.archive.org/cdx/search/cdx"
                f"?url={query_url}&output=json&limit=10&fl=timestamp,statuscode,mimetype&collapse=digest&from=&to="
            )
            r = await client.get(cdx_url)
            rows = r.json() if r.status_code == 200 else []

            # Availability API for latest snapshot
            avail_r = await client.get(
                f"https://archive.org/wayback/available?url={query_url}"
            )
            avail = avail_r.json() if avail_r.status_code == 200 else {}

        snapshots = []
        if len(rows) > 1:  # first row is header
            header = rows[0]
            for row in rows[1:]:
                snap = dict(zip(header, row))
                ts = snap.get("timestamp", "")
                if ts:
                    snap["human"] = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}"
                    snap["archive_url"] = f"https://web.archive.org/web/{ts}/{query_url}"
                snapshots.append(snap)

        closest = avail.get("archived_snapshots", {}).get("closest", {})
        return {
            "url":       query_url,
            "available": closest.get("available", False),
            "closest":   closest.get("url", ""),
            "timestamp": closest.get("timestamp", ""),
            "snapshots": snapshots,
        }
    except Exception as e:
        return {"error": str(e)}


async def dmarc_spf(domain: str) -> dict:
    """Check SPF, DMARC and DKIM (default selector) via DNS TXT records."""
    try:
        import dns.resolver
        results = {"domain": domain, "spf": None, "dmarc": None, "dkim": {}}

        # SPF
        try:
            txts = dns.resolver.resolve(domain, "TXT")
            for r in txts:
                val = r.to_text().strip('"')
                if val.startswith("v=spf1"):
                    results["spf"] = val
                    break
        except Exception:
            pass

        # DMARC
        try:
            txts = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in txts:
                val = r.to_text().strip('"')
                if val.startswith("v=DMARC1"):
                    results["dmarc"] = val
                    break
        except Exception:
            pass

        # DKIM — common selectors
        for sel in ["default", "google", "mail", "dkim", "s1", "s2", "k1"]:
            try:
                txts = dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                for r in txts:
                    val = r.to_text().strip('"')
                    if "v=DKIM1" in val or "p=" in val:
                        results["dkim"][sel] = val[:120] + "…" if len(val) > 120 else val
                        break
            except Exception:
                pass

        # Analysis
        analysis = []
        if not results["spf"]:
            analysis.append("⚠ Sin registro SPF — riesgo de email spoofing")
        else:
            if "-all" in results["spf"]:
                analysis.append("✓ SPF con política estricta (-all)")
            elif "~all" in results["spf"]:
                analysis.append("~ SPF con política suave (~all)")
            else:
                analysis.append("⚠ SPF sin política de rechazo")
        if not results["dmarc"]:
            analysis.append("⚠ Sin registro DMARC — correos falsos no se bloquean")
        else:
            if "p=reject" in results["dmarc"]:
                analysis.append("✓ DMARC con p=reject (protección máxima)")
            elif "p=quarantine" in results["dmarc"]:
                analysis.append("~ DMARC con p=quarantine")
            else:
                analysis.append("⚠ DMARC en modo monitor (p=none)")
        if not results["dkim"]:
            analysis.append("⚠ Sin DKIM encontrado en selectores comunes")
        else:
            analysis.append(f"✓ DKIM encontrado ({', '.join(results['dkim'].keys())})")
        results["analysis"] = analysis
        return results
    except Exception as e:
        return {"error": str(e)}


async def robots_txt(domain: str) -> dict:
    """Fetch robots.txt and sitemap.xml (no auth needed)."""
    if not domain.startswith("http"):
        domain = f"https://{domain}"
    domain = domain.rstrip("/")
    out = {"domain": domain, "robots": None, "sitemap_urls": [], "disallowed": [], "allowed": [], "error": None}
    try:
        async with httpx.AsyncClient(timeout=12, headers=_HEADERS, follow_redirects=True) as client:
            r = await client.get(f"{domain}/robots.txt")
            if r.status_code == 200:
                text = r.text
                out["robots"] = text[:4000]
                for line in text.splitlines():
                    l = line.strip()
                    if l.lower().startswith("disallow:"):
                        path = l[9:].strip()
                        if path:
                            out["disallowed"].append(path)
                    elif l.lower().startswith("allow:"):
                        path = l[6:].strip()
                        if path and path != "/":
                            out["allowed"].append(path)
                    elif l.lower().startswith("sitemap:"):
                        out["sitemap_urls"].append(l[8:].strip())
            else:
                out["error"] = f"robots.txt devolvió HTTP {r.status_code}"
    except Exception as e:
        out["error"] = str(e)
    return out


# ══════════════════════════════════════════════════════════
#  IP / RED
# ══════════════════════════════════════════════════════════

async def ip_geolocate(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10, headers=_HEADERS) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}"
                "?fields=status,message,country,countryCode,region,regionName,"
                "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            )
            data = r.json()
            if data.get("status") == "success":
                return data
            return {"error": data.get("message", "Lookup failed")}
    except Exception as e:
        return {"error": str(e)}


async def reverse_dns(ip: str) -> dict:
    """PTR record + all A records for that hostname."""
    try:
        import dns.resolver
        result = {"ip": ip, "hostnames": [], "a_records": {}}
        # PTR lookup
        try:
            rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            ptrs = dns.resolver.resolve(rev, "PTR")
            result["hostnames"] = [str(p).rstrip(".") for p in ptrs]
        except Exception:
            # Fallback: socket
            try:
                host = socket.gethostbyaddr(ip)
                result["hostnames"] = [host[0]] + list(host[1])
            except Exception:
                pass
        # Forward lookup of each hostname
        for h in result["hostnames"][:3]:
            try:
                ars = dns.resolver.resolve(h, "A")
                result["a_records"][h] = [str(a) for a in ars]
            except Exception:
                pass
        if not result["hostnames"]:
            result["note"] = "Sin registro PTR — IP sin hostname inverso"
        return result
    except Exception as e:
        return {"error": str(e)}


async def asn_lookup(query: str) -> dict:
    """ASN/BGP info via BGPView API (free, no key)."""
    try:
        async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
            # Determine if query is ASN number, IP, or prefix
            query = query.strip()
            if re.match(r"^(AS)?\d+$", query, re.I):
                asn_num = re.sub(r"^AS", "", query, flags=re.I)
                r = await client.get(f"https://api.bgpview.io/asn/{asn_num}")
                data = r.json()
                if data.get("status") == "ok":
                    d = data["data"]
                    prefixes_r = await client.get(f"https://api.bgpview.io/asn/{asn_num}/prefixes")
                    prefixes_data = prefixes_r.json()
                    v4 = [p["prefix"] for p in prefixes_data.get("data", {}).get("ipv4_prefixes", [])[:20]]
                    return {
                        "asn":         f"AS{d.get('asn')}",
                        "name":        d.get("name", ""),
                        "description": d.get("description_short", "") or d.get("description_full", [""])[0],
                        "country":     d.get("country_code", ""),
                        "rir":         d.get("rir_allocation", {}).get("rir_name", ""),
                        "website":     d.get("website", ""),
                        "prefixes_v4": v4,
                    }
                return {"error": data.get("status_message", "ASN not found")}

            elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
                r = await client.get(f"https://api.bgpview.io/ip/{query}")
                data = r.json()
                if data.get("status") == "ok":
                    d = data["data"]
                    prefixes = d.get("prefixes", [])
                    result = {
                        "ip":       query,
                        "rir":      d.get("rir_allocation", {}).get("rir_name", ""),
                        "prefixes": [],
                    }
                    for p in prefixes[:5]:
                        asn_info = p.get("asn", {})
                        result["prefixes"].append({
                            "prefix":  p.get("prefix", ""),
                            "asn":     f"AS{asn_info.get('asn', '')}",
                            "name":    asn_info.get("name", ""),
                            "country": asn_info.get("country_code", ""),
                            "description": asn_info.get("description", ""),
                        })
                    return result
                return {"error": "IP not found"}
            else:
                return {"error": "Introduce una IP o número ASN (ej: AS1234 o 8.8.8.8)"}
    except Exception as e:
        return {"error": str(e)}


async def shodan_lookup(query: str) -> dict:
    if not SHODAN_KEY:
        return {"error": "SHODAN_API_KEY no configurado en .env"}
    try:
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))
        async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
            if is_ip:
                r = await client.get(f"https://api.shodan.io/shodan/host/{query}?key={SHODAN_KEY}")
            else:
                r = await client.get(
                    f"https://api.shodan.io/shodan/host/search?key={SHODAN_KEY}&query={query}&facets=org,os"
                )
        return r.json()
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════
#  EMAIL
# ══════════════════════════════════════════════════════════

async def email_verify(email: str) -> dict:
    """Verify email: format, MX records, disposable domain check."""
    result = {"email": email, "format_valid": False, "mx_records": [], "disposable": False, "notes": []}
    # Format
    m = re.match(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$", email)
    if not m:
        result["notes"].append("⚠ Formato de email inválido")
        return result
    result["format_valid"] = True
    domain = m.group(1).lower()
    result["domain"] = domain

    # MX records
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, "MX")
        result["mx_records"] = sorted(
            [{"priority": r.preference, "exchange": str(r.exchange).rstrip(".")} for r in mx],
            key=lambda x: x["priority"]
        )
        result["notes"].append(f"✓ Dominio acepta correo ({len(result['mx_records'])} servidores MX)")
    except Exception:
        result["notes"].append("⚠ Sin registros MX — dominio no acepta email")

    # Disposable domains list (common ones)
    DISPOSABLE = {
        "mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com",
        "throwaway.email","yopmail.com","sharklasers.com","guerrillamailblock.com",
        "grr.la","guerrillamail.info","guerrillamail.biz","guerrillamail.de",
        "guerrillamail.net","guerrillamail.org","spam4.me","trashmail.at",
        "trashmail.io","trashmail.me","trashmail.xyz","dispostable.com",
        "maildrop.cc","mailnull.com","spamgourmet.com","spamgourmet.net",
        "spamgourmet.org","fakeinbox.com","getairmail.com","mailnesia.com",
        "spamex.com","spamfree24.org","spamgob.com","spamhereplease.com",
    }
    if domain in DISPOSABLE:
        result["disposable"] = True
        result["notes"].append("⚠ Dominio de email desechable (temporal)")
    else:
        result["notes"].append("✓ Dominio no identificado como temporal")

    # Check if domain has A record (exists)
    try:
        import dns.resolver
        dns.resolver.resolve(domain, "A")
        result["domain_exists"] = True
    except Exception:
        result["domain_exists"] = False
        result["notes"].append("⚠ Dominio sin registro A — puede no existir")

    return result


async def hibp_check(email_or_domain: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
            hibp_headers = {**_HEADERS, "hibp-api-key": ""}
            if "@" in email_or_domain:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_or_domain}?truncateResponse=false"
            else:
                url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{email_or_domain}"
            r = await client.get(url, headers=hibp_headers)
            if r.status_code == 200:
                return {"target": email_or_domain, "breaches": r.json()}
            elif r.status_code == 404:
                return {"target": email_or_domain, "breaches": [], "message": "Sin brechas encontradas."}
            elif r.status_code == 401:
                return {"error": "HIBP requiere API key de pago para búsqueda por email. Dominio funciona sin key."}
            else:
                return {"error": f"HIBP devolvió HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


async def hunter_io(domain: str) -> dict:
    """Hunter.io email finder (free tier: 25 searches/month, no credit card)."""
    if not HUNTER_KEY:
        return {
            "error": "HUNTER_API_KEY no configurado en .env",
            "info": "Obtén API key gratuita en https://hunter.io (25 búsquedas/mes gratis)",
        }
    try:
        async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
            r = await client.get(
                f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_KEY}&limit=20"
            )
            data = r.json()
            d = data.get("data", {})
            return {
                "domain":       domain,
                "organization": d.get("organization", ""),
                "total_emails": d.get("total", 0),
                "pattern":      d.get("pattern", ""),
                "emails":       [
                    {
                        "email":      e.get("value"),
                        "type":       e.get("type"),
                        "confidence": e.get("confidence"),
                        "first_name": e.get("first_name"),
                        "last_name":  e.get("last_name"),
                        "position":   e.get("position"),
                        "linkedin":   e.get("linkedin"),
                    }
                    for e in d.get("emails", [])
                ],
            }
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════
#  URL / WEB
# ══════════════════════════════════════════════════════════

async def http_headers(url: str) -> dict:
    """Fetch HTTP response headers and detect security headers."""
    if not url.startswith("http"):
        url = f"https://{url}"
    try:
        async with httpx.AsyncClient(timeout=15, headers=_HEADERS, follow_redirects=True) as client:
            r = await client.get(url)
            headers = dict(r.headers)
            # Security header analysis
            SECURITY_HEADERS = {
                "strict-transport-security": ("HSTS", True),
                "content-security-policy":   ("CSP", True),
                "x-frame-options":           ("X-Frame-Options", True),
                "x-content-type-options":    ("X-Content-Type-Options", True),
                "x-xss-protection":          ("X-XSS-Protection", True),
                "referrer-policy":           ("Referrer-Policy", True),
                "permissions-policy":        ("Permissions-Policy", True),
                "access-control-allow-origin": ("CORS", False),
            }
            security = {}
            for hdr, (name, good) in SECURITY_HEADERS.items():
                val = headers.get(hdr)
                security[name] = {"present": bool(val), "value": val or ""}

            tech_hints = {}
            for hdr in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
                if hdr in headers:
                    tech_hints[hdr] = headers[hdr]

            return {
                "url":         str(r.url),
                "status_code": r.status_code,
                "redirect_chain": [str(h.url) for h in r.history],
                "headers":     headers,
                "security":    security,
                "tech_hints":  tech_hints,
                "score": sum(1 for v in security.values() if v["present"] and
                             next((g for _, g in [SECURITY_HEADERS.get(k, ("", True))
                                                   for k in SECURITY_HEADERS
                                                   if next((n for n, g2 in [SECURITY_HEADERS.get(k, ("", True))]
                                                            if n == v), None)]), True)),
            }
    except Exception as e:
        return {"error": str(e)}


async def urlscan_search(query: str) -> dict:
    """
    URLscan.io — search is FREE without API key.
    Submit requires free API key (URLSCAN_API_KEY in .env).
    """
    try:
        async with httpx.AsyncClient(timeout=20, headers=_HEADERS) as client:
            # Search existing scans (public, no auth needed)
            r = await client.get(
                f"https://urlscan.io/api/v1/search/?q={query}&size=10",
                headers={**_HEADERS, "Content-Type": "application/json"},
            )
            if r.status_code != 200:
                return {"error": f"URLscan devolvió HTTP {r.status_code}"}
            data = r.json()
            results = []
            for hit in data.get("results", []):
                page = hit.get("page", {})
                task = hit.get("task", {})
                verdicts = hit.get("verdicts", {}).get("overall", {})
                results.append({
                    "url":        page.get("url", ""),
                    "domain":     page.get("domain", ""),
                    "ip":         page.get("ip", ""),
                    "country":    page.get("country", ""),
                    "server":     page.get("server", ""),
                    "title":      page.get("title", ""),
                    "scanned_at": task.get("time", "")[:10],
                    "score":      verdicts.get("score", 0),
                    "malicious":  verdicts.get("malicious", False),
                    "tags":       verdicts.get("tags", []),
                    "screenshot": hit.get("screenshot", ""),
                    "result_url": f"https://urlscan.io/result/{hit.get('_id', '')}/",
                })
            return {
                "query":   query,
                "total":   data.get("total", 0),
                "results": results,
            }
    except Exception as e:
        return {"error": str(e)}


async def virustotal_lookup(target: str) -> dict:
    if not VT_KEY:
        return {"error": "VIRUSTOTAL_API_KEY no configurado en .env"}
    try:
        vt_headers = {**_HEADERS, "x-apikey": VT_KEY}
        is_ip  = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
        is_url = target.startswith("http")
        is_hash = bool(re.match(r"^[a-fA-F0-9]{32,64}$", target))
        async with httpx.AsyncClient(timeout=20, headers=vt_headers) as client:
            if is_ip:
                r = await client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{target}")
            elif is_hash:
                r = await client.get(f"https://www.virustotal.com/api/v3/files/{target}")
            elif is_url:
                import base64
                url_id = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
                r = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}")
            else:
                r = await client.get(f"https://www.virustotal.com/api/v3/domains/{target}")
        data = r.json()
        if "data" in data:
            attrs = data["data"].get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "target":     target,
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "type":       data["data"].get("type", ""),
                "reputation": attrs.get("reputation", 0),
                "tags":       attrs.get("tags", []),
                "categories": attrs.get("categories", {}),
                "full":       attrs,
            }
        return data
    except Exception as e:
        return {"error": str(e)}

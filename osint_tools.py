import os
import json
import re
import socket
import httpx
from datetime import datetime

SHODAN_KEY        = os.getenv("SHODAN_API_KEY",        "")
VT_KEY            = os.getenv("VIRUSTOTAL_API_KEY",   "")
HUNTER_KEY        = os.getenv("HUNTER_API_KEY",       "")
URLSCAN_KEY       = os.getenv("URLSCAN_API_KEY",       "")
ABUSEIPDB_KEY     = os.getenv("ABUSEIPDB_API_KEY",     "")
MALWAREBAZAAR_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")
HIBP_KEY          = os.getenv("HIBP_API_KEY",          "")
LEAKRADAR_KEY     = os.getenv("LEAKRADAR_API_KEY",     "")
ANYRUN_KEY        = os.getenv("ANYRUN_API_KEY",        "")

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


async def subdomains_combined(domain: str) -> dict:
    """Find subdomains from crt.sh + HackerTarget, deduped with source tags."""
    import asyncio

    async def from_crtsh():
        results = {}
        try:
            async with httpx.AsyncClient(timeout=20, headers=_HEADERS) as client:
                r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if r.status_code == 200:
                    for e in r.json():
                        for sub in e.get("name_value", "").split("\n"):
                            sub = sub.strip().lstrip("*.")
                            if sub.endswith(domain) and sub != domain:
                                results[sub] = results.get(sub, set()) | {"crt.sh"}
        except Exception:
            pass
        return results

    async def from_hackertarget():
        results = {}
        try:
            async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
                r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
                if r.status_code == 200 and "error" not in r.text[:30].lower():
                    for line in r.text.splitlines():
                        parts = line.split(",")
                        if len(parts) >= 1:
                            sub = parts[0].strip()
                            if sub.endswith(domain) and sub != domain:
                                results[sub] = results.get(sub, set()) | {"HackerTarget"}
        except Exception:
            pass
        return results

    crt_res, ht_res = await asyncio.gather(from_crtsh(), from_hackertarget())

    # Merge
    merged: dict[str, set] = {}
    for sub, sources in crt_res.items():
        merged.setdefault(sub, set()).update(sources)
    for sub, sources in ht_res.items():
        merged.setdefault(sub, set()).update(sources)

    entries = sorted(
        [{"subdomain": sub, "sources": sorted(srcs)} for sub, srcs in merged.items()],
        key=lambda x: x["subdomain"]
    )
    return {
        "domain":  domain,
        "entries": entries,
        "count":   len(entries),
        "sources": {"crt.sh": len(crt_res), "hackertarget": len(ht_res)},
    }


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
    hibp_headers = {**_HEADERS, "hibp-api-key": HIBP_KEY, "User-Agent": "CyberKB"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            if "@" in email_or_domain:
                if not HIBP_KEY:
                    return {
                        "error": "HIBP_API_KEY no configurada — requerida para búsqueda por email",
                        "info": "Obtén API key en https://haveibeenpwned.com/API/Key (servicio de pago ~3.50$/mes)",
                    }
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email_or_domain}?truncateResponse=false"
            else:
                # Domain search works without key
                url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{email_or_domain}"
            r = await client.get(url, headers=hibp_headers)
            if r.status_code == 200:
                breaches = r.json()
                # Normalize: domain endpoint returns dict {email: [breaches]}, email returns list
                if isinstance(breaches, dict):
                    flat = []
                    for email, blist in breaches.items():
                        for b in blist:
                            flat.append({"Email": email, "Name": b, "BreachDate": "", "DataClasses": []})
                    return {"target": email_or_domain, "breaches": flat, "is_domain": True}
                return {"target": email_or_domain, "breaches": breaches}
            elif r.status_code == 404:
                return {"target": email_or_domain, "breaches": [], "message": "✓ Sin brechas encontradas."}
            elif r.status_code == 401:
                return {"error": "HIBP_API_KEY inválida o expirada"}
            elif r.status_code == 429:
                return {"error": "Rate limit HIBP — espera unos segundos antes de reintentar"}
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


# ══════════════════════════════════════════════════════════
#  THREAT INTELLIGENCE
# ══════════════════════════════════════════════════════════

def _ts(unix: int | None) -> str:
    """Unix timestamp → human readable date string."""
    if not unix:
        return ""
    try:
        return datetime.utcfromtimestamp(unix).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(unix)


async def hash_vt(hash_str: str) -> dict:
    """Detailed VirusTotal file/hash analysis for threat intelligence."""
    if not VT_KEY:
        return {"error": "VIRUSTOTAL_API_KEY no configurado en .env",
                "info": "Obtén API key gratuita en https://www.virustotal.com/gui/join-us"}
    hash_str = hash_str.strip().lower()
    length = len(hash_str)
    if length == 32:
        hash_type = "MD5"
    elif length == 40:
        hash_type = "SHA1"
    elif length == 64:
        hash_type = "SHA256"
    else:
        return {"error": f"Hash inválido — longitud {length}. Esperado MD5(32), SHA1(40) o SHA256(64)."}

    vt_headers = {**_HEADERS, "x-apikey": VT_KEY}
    try:
        async with httpx.AsyncClient(timeout=25, headers=vt_headers) as client:
            r = await client.get(f"https://www.virustotal.com/api/v3/files/{hash_str}")
            if r.status_code == 404:
                return {"error": "Hash no encontrado en VirusTotal — muestra desconocida o nunca subida."}
            if r.status_code != 200:
                return {"error": f"VirusTotal devolvió HTTP {r.status_code}"}
            data = r.json()

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())
        detected = stats.get("malicious", 0) + stats.get("suspicious", 0)

        # Malware name / family
        threat_cls = attrs.get("popular_threat_classification", {})
        suggested_label = threat_cls.get("suggested_threat_label", "")
        families = [f.get("value", "") for f in threat_cls.get("popular_threat_category", [])]
        family = families[0] if families else ""

        # Alternative names from AV results
        av_results = attrs.get("last_analysis_results", {})
        alt_names = {}
        for av, res in av_results.items():
            if res.get("category") in ("malicious", "suspicious") and res.get("result"):
                alt_names[av] = res["result"]
        # Top 15 AV detections
        top_detections = [{"av": av, "result": name} for av, name in list(alt_names.items())[:15]]

        # Names list
        names = attrs.get("names", [])[:10]

        # Votes
        votes = attrs.get("total_votes", {})
        community_score = votes.get("malicious", 0) - votes.get("harmless", 0)

        # MITRE ATT&CK from sigma/crowdsourced
        mitre_techniques = []
        for sigma in attrs.get("sigma_analysis_results", [])[:5]:
            for tactic in sigma.get("match_context", [{}]):
                pass  # sigma is complex; skip deep parse
        # Try crowdsourced IDS
        for ids_r in attrs.get("crowdsourced_ids_results", [])[:5]:
            for alert in ids_r.get("alert_context", []):
                pass

        # Simpler: check sandbox verdicts for MITRE
        for verdict in attrs.get("sandbox_verdicts", {}).values():
            for t in verdict.get("malware_classification", []):
                pass

        # C2 / contacted IPs/domains (from network indicators if available)
        contacted_urls = attrs.get("contacted_urls", [])[:10]
        contacted_ips  = attrs.get("contacted_ips", [])[:10]
        contacted_domains = attrs.get("contacted_domains", [])[:10]

        # File type info
        file_type = attrs.get("type_description", "") or attrs.get("magic", "")
        file_size = attrs.get("size", 0)
        file_name = attrs.get("meaningful_name", "") or (names[0] if names else "")

        return {
            "hash":              hash_str,
            "hash_type":         hash_type,
            "file_name":         file_name,
            "file_type":         file_type,
            "file_size":         file_size,
            "suggested_label":   suggested_label,
            "family":            family,
            "detected":          detected,
            "total_engines":     total,
            "community_score":   community_score,
            "created_at":        _ts(attrs.get("creation_date")),
            "first_submission":  _ts(attrs.get("first_submission_date")),
            "first_seen_itw":    _ts(attrs.get("first_seen_itw_date")),
            "last_analysis":     _ts(attrs.get("last_analysis_date")),
            "names":             names,
            "top_detections":    top_detections,
            "contacted_urls":    contacted_urls,
            "contacted_ips":     contacted_ips,
            "contacted_domains": contacted_domains,
            "stats":             stats,
            "tags":              attrs.get("tags", []),
        }
    except Exception as e:
        return {"error": str(e)}


async def ip_abuseipdb(ip: str) -> dict:
    """AbuseIPDB IP reputation check."""
    if not ABUSEIPDB_KEY:
        return {
            "error": "ABUSEIPDB_API_KEY no configurado en .env",
            "info": "Obtén API key gratuita (1000 req/día) en https://www.abuseipdb.com/api",
        }
    try:
        headers = {**_HEADERS, "Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers=headers,
            )
            if r.status_code == 422:
                return {"error": f"IP inválida: {ip}"}
            if r.status_code == 401:
                return {"error": "ABUSEIPDB_API_KEY inválida o expirada"}
            if r.status_code != 200:
                return {"error": f"AbuseIPDB devolvió HTTP {r.status_code}"}
            data = r.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("reports", [])[:5]

        # Category codes → names
        CAT = {
            1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders",
            4:"DDoS Attack", 5:"FTP Brute-Force", 6:"Ping of Death",
            7:"Phishing", 8:"Fraud VoIP", 9:"Open Proxy", 10:"Web Spam",
            11:"Email Spam", 12:"Blog Spam", 13:"VPN IP", 14:"Port Scan",
            15:"Hacking", 16:"SQL Injection", 17:"Spoofing", 18:"Brute-Force",
            19:"Bad Web Bot", 20:"Exploited Host", 21:"Web App Attack",
            22:"SSH", 23:"IoT Targeted",
        }
        parsed_reports = []
        for rep in reports:
            cats = [CAT.get(c, f"Cat {c}") for c in rep.get("categories", [])]
            parsed_reports.append({
                "date":       rep.get("reportedAt", "")[:10],
                "categories": cats,
                "comment":    (rep.get("comment") or "")[:200],
                "country":    rep.get("reporterCountryCode", ""),
            })

        return {
            "ip":             ip,
            "score":          score,
            "country":        data.get("countryCode", ""),
            "isp":            data.get("isp", ""),
            "domain":         data.get("domain", ""),
            "usage_type":     data.get("usageType", ""),
            "total_reports":  data.get("totalReports", 0),
            "distinct_users": data.get("numDistinctUsers", 0),
            "last_reported":  (data.get("lastReportedAt") or "")[:10],
            "is_tor":         data.get("isTor", False),
            "is_proxy":       data.get("isPublicAccessPoint", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "reports":        parsed_reports,
        }
    except Exception as e:
        return {"error": str(e)}


async def hash_malwarebazaar(hash_str: str) -> dict:
    """MalwareBazaar hash lookup — requires free API key from abuse.ch."""
    if not MALWAREBAZAAR_KEY:
        return {
            "error": "MALWAREBAZAAR_API_KEY no configurada en .env",
            "info": "Regístrate gratis en https://bazaar.abuse.ch/api/ para obtener tu API key.",
        }
    hash_str = hash_str.strip().lower()
    if len(hash_str) != 64:
        return {"error": "MalwareBazaar requiere hash SHA256 (64 caracteres hex)"}
    try:
        mb_headers = {**_HEADERS, "Auth-Key": MALWAREBAZAAR_KEY}
        async with httpx.AsyncClient(timeout=20, headers=mb_headers) as client:
            r = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": hash_str},
            )
            data = r.json()

        if data.get("query_status") == "hash_not_found":
            return {"error": "Hash no encontrado en MalwareBazaar — muestra desconocida."}
        if data.get("query_status") != "ok":
            return {"error": f"MalwareBazaar: {data.get('query_status', 'error desconocido')}"}

        samples = data.get("data", [])
        if not samples:
            return {"error": "Sin datos para este hash"}

        s = samples[0]
        return {
            "sha256":      s.get("sha256_hash", ""),
            "sha1":        s.get("sha1_hash", ""),
            "md5":         s.get("md5_hash", ""),
            "file_name":   s.get("file_name", ""),
            "file_size":   s.get("file_size", 0),
            "file_type":   s.get("file_type", ""),
            "mime_type":   s.get("file_type_mime", ""),
            "first_seen":  s.get("first_seen", ""),
            "last_seen":   s.get("last_seen", ""),
            "tags":        s.get("tags", []) or [],
            "signature":   s.get("signature", ""),
            "origin":      s.get("origin_country", ""),
            "imphash":     s.get("imphash", ""),
            "ssdeep":      s.get("ssdeep", ""),
            "tlsh":        s.get("tlsh", ""),
            "reporter":    s.get("reporter", ""),
            "anonymous":   s.get("anonymous", 0),
            "intelligence": s.get("intelligence", {}),
            "delivery_method": s.get("delivery_method", ""),
            "comment":     s.get("comment", ""),
        }
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════
#  LEAK SEARCH
# ══════════════════════════════════════════════════════════

def _mask_password(pwd: str) -> str:
    """Show first 2 + last 2 chars, mask middle."""
    if not pwd:
        return "****"
    if len(pwd) <= 4:
        return "*" * len(pwd)
    return pwd[:2] + "*" * (len(pwd) - 4) + pwd[-2:]


async def leakradar_search(query: str) -> dict:
    """Credential search by email or domain (DeHashed-compatible API)."""
    if not LEAKRADAR_KEY:
        return {
            "error": "LEAKRADAR_API_KEY no configurada en .env",
            "info": "Obtén API key en https://dehashed.com (compatible) o https://leakradar.io",
        }
    query = query.strip()
    is_domain = query.startswith("@") or ("@" not in query)
    search_term = query.lstrip("@")

    try:
        # DeHashed-compatible search endpoint
        search_query = f"domain:{search_term}" if is_domain else f"email:{search_term}"
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(
                "https://api.dehashed.com/search",
                params={"query": search_query, "size": 20},
                headers={
                    **_HEADERS,
                    "Accept": "application/json",
                    "Authorization": f"Bearer {LEAKRADAR_KEY}",
                },
            )
            if r.status_code == 401:
                return {"error": "LEAKRADAR_API_KEY inválida o expirada"}
            if r.status_code == 402:
                return {"error": "Créditos insuficientes en cuenta"}
            if r.status_code != 200:
                return {"error": f"LeakRadar devolvió HTTP {r.status_code}: {r.text[:200]}"}
            data = r.json()

        entries = data.get("entries", []) or []
        results = []
        for e in entries[:50]:
            pwd = e.get("password", "")
            results.append({
                "email":           e.get("email", ""),
                "username":        e.get("username", ""),
                "password":        _mask_password(pwd) if pwd else "",
                "hashed_password": e.get("hashed_password", ""),
                "database":        e.get("database_name", ""),
                "name":            e.get("name", ""),
                "phone":           e.get("phone", ""),
            })

        return {
            "query":   query,
            "total":   data.get("total", len(results)),
            "balance": data.get("balance"),
            "results": results,
        }
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════════════════
#  ANY.RUN
# ══════════════════════════════════════════════════════════

async def anyrun_lookup(hash_str: str) -> dict:
    """Query Any.run public sandbox reports by SHA256 hash."""
    hash_str = hash_str.strip().lower()
    if len(hash_str) != 64:
        return {"error": "Any.run requiere SHA256 (64 caracteres hex)", "link": None}

    direct_link = f"https://any.run/malware-trends/?q={hash_str}"

    if not ANYRUN_KEY:
        return {
            "note": "ANYRUN_API_KEY no configurada — mostrando enlace directo",
            "link": direct_link,
            "tasks": [],
        }

    try:
        headers = {
            **_HEADERS,
            "Authorization": f"API-Key {ANYRUN_KEY}",
        }
        async with httpx.AsyncClient(timeout=20, headers=headers) as client:
            r = await client.get(
                "https://api.any.run/v1/tasks/",
                params={"hash": hash_str, "skip": 0, "limit": 5},
            )
            if r.status_code == 401:
                return {"error": "ANYRUN_API_KEY inválida o expirada", "link": direct_link, "tasks": []}
            if r.status_code == 404 or r.status_code == 200:
                data = r.json() if r.status_code == 200 else {}
            else:
                return {"error": f"Any.run devolvió HTTP {r.status_code}", "link": direct_link, "tasks": []}

        tasks = data.get("data", {}).get("tasks", []) or []
        parsed = []
        for t in tasks[:5]:
            parsed.append({
                "task_id":    t.get("uuid", ""),
                "name":       t.get("name", ""),
                "verdict":    t.get("verdict", ""),
                "threat_name":t.get("mainObject", {}).get("threatName", ""),
                "mitre":      [m.get("id", "") for m in t.get("mitre", [])[:10]],
                "date":       t.get("date", "")[:10],
                "url":        f"https://app.any.run/tasks/{t.get('uuid', '')}" if t.get("uuid") else "",
            })

        return {
            "hash":  hash_str,
            "total": data.get("data", {}).get("total", len(parsed)),
            "tasks": parsed,
            "link":  direct_link,
        }
    except Exception as e:
        return {"error": str(e), "link": direct_link, "tasks": []}

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import OsintResult
import osint_tools as osint

from layers.routers_functions import _save_osint


router = APIRouter()


@router.post("/api/osint/whois")
async def api_whois(domain: str, db: Session = Depends(get_db)):
    result = await osint.whois_lookup(domain)
    _save_osint(domain, "whois", result, db)
    return result


@router.post("/api/osint/dns")
async def api_dns(domain: str, db: Session = Depends(get_db)):
    result = await osint.dns_lookup(domain)
    _save_osint(domain, "dns", result, db)
    return result


@router.post("/api/osint/subdomains")
async def api_subdomains(domain: str, db: Session = Depends(get_db)):
    result = await osint.subdomains_combined(domain)
    _save_osint(domain, "subdomains", result, db)
    return result


@router.post("/api/osint/ssl")
async def api_ssl(domain: str, db: Session = Depends(get_db)):
    result = await osint.ssl_cert(domain)
    _save_osint(domain, "ssl", result, db)
    return result


@router.post("/api/osint/wayback")
async def api_wayback(url: str, db: Session = Depends(get_db)):
    result = await osint.wayback(url)
    _save_osint(url, "wayback", result, db)
    return result


@router.post("/api/osint/dmarc")
async def api_dmarc(domain: str, db: Session = Depends(get_db)):
    result = await osint.dmarc_spf(domain)
    _save_osint(domain, "dmarc", result, db)
    return result


@router.post("/api/osint/robots")
async def api_robots(domain: str, db: Session = Depends(get_db)):
    result = await osint.robots_txt(domain)
    _save_osint(domain, "robots", result, db)
    return result


@router.post("/api/osint/ip")
async def api_ip(ip: str, db: Session = Depends(get_db)):
    result = await osint.ip_geolocate(ip)
    _save_osint(ip, "ip", result, db)
    return result


@router.post("/api/osint/reverse-dns")
async def api_rdns(ip: str, db: Session = Depends(get_db)):
    result = await osint.reverse_dns(ip)
    _save_osint(ip, "reverse-dns", result, db)
    return result


@router.post("/api/osint/asn")
async def api_asn(query: str, db: Session = Depends(get_db)):
    result = await osint.asn_lookup(query)
    _save_osint(query, "asn", result, db)
    return result


@router.post("/api/osint/shodan")
async def api_shodan(query: str, db: Session = Depends(get_db)):
    result = await osint.shodan_lookup(query)
    _save_osint(query, "shodan", result, db)
    return result


@router.post("/api/osint/email-verify")
async def api_email_verify(email: str, db: Session = Depends(get_db)):
    import asyncio
    verify_task = osint.email_verify(email)
    hibp_task   = osint.hibp_check(email)
    result, hibp_result = await asyncio.gather(verify_task, hibp_task)
    result["hibp"] = hibp_result
    _save_osint(email, "email-verify", result, db)
    return result


@router.post("/api/osint/hibp")
async def api_hibp(target: str, db: Session = Depends(get_db)):
    result = await osint.hibp_check(target)
    _save_osint(target, "hibp", result, db)
    return result


@router.post("/api/osint/hunter")
async def api_hunter(domain: str, db: Session = Depends(get_db)):
    result = await osint.hunter_io(domain)
    _save_osint(domain, "hunter", result, db)
    return result


@router.post("/api/osint/leakradar")
async def api_leakradar(query: str, db: Session = Depends(get_db)):
    result = await osint.leakradar_search(query)
    _save_osint(query, "leakradar", result, db)
    return result


@router.post("/api/osint/headers")
async def api_headers(url: str, db: Session = Depends(get_db)):
    result = await osint.http_headers(url)
    _save_osint(url, "headers", result, db)
    return result


@router.post("/api/osint/urlscan")
async def api_urlscan(query: str, db: Session = Depends(get_db)):
    result = await osint.urlscan_search(query)
    _save_osint(query, "urlscan", result, db)
    return result


@router.post("/api/osint/virustotal")
async def api_vt(target: str, db: Session = Depends(get_db)):
    result = await osint.virustotal_lookup(target)
    _save_osint(target, "virustotal", result, db)
    return result


@router.post("/api/osint/hash-vt")
async def api_hash_vt(hash: str, db: Session = Depends(get_db)):
    result = await osint.hash_vt(hash)
    _save_osint(hash, "hash-vt", result, db)
    return result


@router.post("/api/osint/abuseipdb")
async def api_abuseipdb(ip: str, db: Session = Depends(get_db)):
    result = await osint.ip_abuseipdb(ip)
    _save_osint(ip, "abuseipdb", result, db)
    return result


@router.post("/api/osint/malwarebazaar")
async def api_malwarebazaar(hash: str, db: Session = Depends(get_db)):
    result = await osint.hash_malwarebazaar(hash)
    _save_osint(hash, "malwarebazaar", result, db)
    return result


@router.get("/api/osint/history")
def osint_history(db: Session = Depends(get_db)):
    rows = db.query(OsintResult).order_by(OsintResult.created_at.desc()).limit(50).all()
    return [
        {
            "id": r.id,
            "query": r.query,
            "type": r.query_type,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/api/osint/history/{result_id}")
def osint_result(result_id: int, db: Session = Depends(get_db)):
    r = db.query(OsintResult).filter(OsintResult.id == result_id).first()
    if not r:
        raise HTTPException(404, "Not found")
    return json.loads(r.result or "{}")
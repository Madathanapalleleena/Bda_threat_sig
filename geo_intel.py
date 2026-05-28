"""
geo_intel.py — IP Geolocation + ASN risk enrichment (no paid key needed)
Uses ip-api.com (free, 45 req/min) as primary, falls back to ipinfo.io
"""

import httpx
import asyncio
from typing import Optional

# ── Risk scoring tables ────────────────────────────────────────────────────

# ASN prefixes known for abuse hosting
HIGH_RISK_ASN_KEYWORDS = [
    "choopa", "vultr", "frantech", "hostkey", "selectel", "serverius",
    "qhoster", "sharktech", "ecatel", "leaseweb", "m247", "combahton",
    "pq.hosting", "alexhost", "psychz", "nexeon", "inferno",
]

HIGH_RISK_COUNTRIES   = {"CN","RU","KP","IR","SY","LY","IQ","AF","SD","BY","VE","CU"}
MEDIUM_RISK_COUNTRIES = {"UA","RO","BR","NG","PK","BD","IN","VN","ID","PH","MX","EG"}

CONTINENT_NAMES = {
    "AF": "Africa", "AN": "Antarctica", "AS": "Asia", "EU": "Europe",
    "NA": "North America", "OC": "Oceania", "SA": "South America",
}

COUNTRY_FLAGS = {
    "CN":"🇨🇳","RU":"🇷🇺","US":"🇺🇸","DE":"🇩🇪","FR":"🇫🇷","GB":"🇬🇧",
    "NL":"🇳🇱","BR":"🇧🇷","IN":"🇮🇳","KP":"🇰🇵","IR":"🇮🇷","UA":"🇺🇦",
    "RO":"🇷🇴","PK":"🇵🇰","NG":"🇳🇬","JP":"🇯🇵","KR":"🇰🇷","AU":"🇦🇺",
    "CA":"🇨🇦","IT":"🇮🇹","ES":"🇪🇸","SE":"🇸🇪","CH":"🇨🇭","SG":"🇸🇬",
    "BY":"🇧🇾","VE":"🇻🇪","TR":"🇹🇷","TH":"🇹🇭","ID":"🇮🇩","PH":"🇵🇭",
}


async def geolocate(ip: str) -> dict:
    """Fetch geolocation + ASN data for an IP address."""
    geo = {}
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            # ip-api.com — free tier, 45 req/min, no key
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": "status,message,country,countryCode,region,regionName,"
                              "city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
                }
            )
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    geo = d
    except Exception as e:
        print(f"[GEO] ip-api.com failed for {ip}: {e}")

    # Fallback: ipinfo.io (free, 50k/month)
    if not geo:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(f"https://ipinfo.io/{ip}/json")
                if resp.status_code == 200:
                    d = resp.json()
                    loc = d.get("loc", "0,0").split(",")
                    geo = {
                        "status":      "success",
                        "country":     d.get("country", ""),
                        "countryCode": d.get("country", ""),
                        "city":        d.get("city", ""),
                        "regionName":  d.get("region", ""),
                        "lat":         float(loc[0]),
                        "lon":         float(loc[1]),
                        "isp":         d.get("org", ""),
                        "org":         d.get("org", ""),
                        "timezone":    d.get("timezone", ""),
                        "as":          d.get("org", ""),
                        "asname":      d.get("org", ""),
                        "hosting":     False,
                        "proxy":       False,
                        "mobile":      False,
                    }
        except Exception as e:
            print(f"[GEO] ipinfo.io fallback also failed for {ip}: {e}")

    return enrich_geo(ip, geo)


def enrich_geo(ip: str, geo: dict) -> dict:
    """Add risk scoring, flag emoji, ASN risk assessment."""
    cc  = geo.get("countryCode", "")
    isp = (geo.get("isp", "") + " " + geo.get("asname", "")).lower()

    # Country risk
    if cc in HIGH_RISK_COUNTRIES:
        geo_risk = "high"
        geo_risk_score = 80
    elif cc in MEDIUM_RISK_COUNTRIES:
        geo_risk = "medium"
        geo_risk_score = 45
    else:
        geo_risk = "low"
        geo_risk_score = 10

    # ASN / hosting risk
    asn_suspicious = any(kw in isp for kw in HIGH_RISK_ASN_KEYWORDS)
    is_hosting     = bool(geo.get("hosting", False))
    is_proxy       = bool(geo.get("proxy",   False))
    is_mobile      = bool(geo.get("mobile",  False))

    if asn_suspicious:
        geo_risk_score = min(100, geo_risk_score + 25)

    flag = COUNTRY_FLAGS.get(cc, "🌐")

    return {
        "ip":            ip,
        "country":       geo.get("country", "Unknown"),
        "country_code":  cc,
        "flag":          flag,
        "city":          geo.get("city", ""),
        "region":        geo.get("regionName", ""),
        "lat":           geo.get("lat", 0),
        "lon":           geo.get("lon", 0),
        "timezone":      geo.get("timezone", ""),
        "isp":           geo.get("isp", "Unknown"),
        "org":           geo.get("org", ""),
        "asn":           geo.get("as", ""),
        "asn_name":      geo.get("asname", ""),
        "is_hosting":    is_hosting,
        "is_proxy":      is_proxy,
        "is_mobile":     is_mobile,
        "asn_suspicious": asn_suspicious,
        "geo_risk":      geo_risk,
        "geo_risk_score": geo_risk_score,
        "source":        "ip-api.com",
    }
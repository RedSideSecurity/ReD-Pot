"""Offline GeoIP (DB-IP Lite mmdb, CC BY 4.0) — never calls an online service.

Looks in RPOT_GEOIP_DIR (default /var/lib/rpot/geoip) for:
  dbip-city-lite.mmdb     (optional, ~130 MB: city + lat/lon)
  dbip-country-lite.mmdb  (country only; the map then uses the country centroid)
  dbip-asn-lite.mmdb      (ASN + organisation)
Any MaxMind-compatible GeoLite2-City/Country/ASN .mmdb works too.
"""
import glob
import ipaddress
import json
import os
import threading
from functools import lru_cache

try:
    import maxminddb
except ImportError:  # geo is optional
    maxminddb = None

_CENTROIDS = None


def centroid(cc):
    """(lat, lon) of a country (ISO-3166 alpha-2): largest-landmass centroid, vendored offline table."""
    global _CENTROIDS
    if _CENTROIDS is None:
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "country_centroids.json")) as f:
                _CENTROIDS = json.load(f)
        except (OSError, ValueError):
            _CENTROIDS = {}
    c = _CENTROIDS.get(str(cc or "").upper())
    return (c[0], c[1]) if c else None


class Geo:
    def __init__(self, directory=None):
        self.dir = directory or os.environ.get("RPOT_GEOIP_DIR", "/var/lib/rpot/geoip")
        self.city = self.country = self.asn = None
        self.lock = threading.Lock()
        self.sources = []
        if maxminddb and os.path.isdir(self.dir):
            for f in sorted(glob.glob(os.path.join(self.dir, "*.mmdb"))):
                low = os.path.basename(f).lower()
                try:
                    db = maxminddb.open_database(f)
                except Exception:
                    continue
                if "asn" in low:
                    self.asn = self.asn or db
                elif "city" in low:
                    self.city = self.city or db
                elif "country" in low:
                    self.country = self.country or db
                else:
                    continue
                self.sources.append(os.path.basename(f))

    @property
    def available(self):
        return bool(self.city or self.country)

    @lru_cache(maxsize=50000)
    def lookup(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not a.is_global:
            return None
        out = {}
        with self.lock:
            rec = None
            if self.city:
                rec = self.city.get(ip)
            if not rec and self.country:
                rec = self.country.get(ip)
            asn = self.asn.get(ip) if self.asn else None
        if rec:
            c = rec.get("country") or {}
            out["cc"] = c.get("iso_code")
            out["country"] = (c.get("names") or {}).get("en")
            city = (rec.get("city") or {}).get("names", {}).get("en")
            if city:
                out["city"] = city
            loc = rec.get("location") or {}
            if "latitude" in loc:
                out["lat"], out["lon"] = round(loc["latitude"], 3), round(loc["longitude"], 3)
        if asn:
            out["asn"] = asn.get("autonomous_system_number")
            out["org"] = asn.get("autonomous_system_organization")
        return out or None

    def locate(self, ip):
        """Map position of a PUBLIC address: city lat/lon when the city DB has it, else the country centroid.
        None for private / unknown addresses. Adds approx=True when only the country is known."""
        g = self.lookup(ip)
        if not g:
            return None
        if g.get("lat") is not None and g.get("lon") is not None:
            return dict(g, approx=False)
        c = centroid(g.get("cc"))
        return dict(g, lat=c[0], lon=c[1], approx=True) if c else None

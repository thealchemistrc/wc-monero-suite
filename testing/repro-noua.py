#!/usr/bin/env python3
"""Replicate the daemon's exact HTTP fingerprint: urllib, NO User-Agent header."""
import urllib.request, urllib.parse, ssl, sys

url = "https://localhost/shop/"
data = urllib.parse.urlencode({"msg": "AAAA-noise", "sig": "ab"*64, "pk": "cd"*32}).encode()
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(url, data=data, method="POST")
# NOTE: deliberately NOT setting User-Agent - xmr-pushd uses raw urllib.parse.urlencode
try:
    with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
        body = r.read()
        print("status:", r.status)
        print("len:", len(body))
        print("--- body head ---")
        print(body[:1200].decode("utf-8", "replace"))
except Exception as e:
    print("ERROR:", e)

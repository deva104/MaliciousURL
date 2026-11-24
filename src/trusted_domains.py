"""Trusted-domain safety net for the API (NOT used in any notebook metric).

A small curated list of very popular domains is answered "safe" without asking
the model, because a false alarm on google.com or onlinesbi.sbi would make
users uninstall the extension. Two rules keep this from becoming a hole:

1. Match on the EXACT registered domain, computed with the same tldextract
   logic as the features (src.features.parse_url). "paypal.com.evil.tk" has the
   registered domain "evil.tk", so it is NOT trusted.
2. NEVER trust hosts or paths where anyone can publish content, even when their
   registered domain is on the list: Google Sites/Forms/Drive, GitHub Pages,
   Firebase, Vercel, Netlify, Blogspot, SharePoint, IPFS gateways, open
   redirects, ... Those always go to the model.
"""
from __future__ import annotations

import re

from .features import parse_url

#: Registered domains (eTLD+1) that are answered "safe" (~150).
TRUSTED_DOMAINS: frozenset[str] = frozenset({
    # search, mail, productivity, cloud
    "google.com", "google.co.in", "gmail.com", "youtube.com", "youtu.be", "gstatic.com",
    "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com",
    "bing.com", "msn.com", "apple.com", "icloud.com", "yahoo.com", "zoom.us", "slack.com",
    "notion.so", "atlassian.com", "adobe.com", "canva.com", "openai.com", "chatgpt.com",
    "anthropic.com", "claude.ai", "cloudflare.com", "mozilla.org", "python.org", "pypi.org",
    "npmjs.com", "github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com",
    "kaggle.com", "w3schools.com", "geeksforgeeks.org", "leetcode.com", "hackerrank.com",
    "codechef.com", "medium.com", "dev.to",
    # social, media, news
    "facebook.com", "instagram.com", "whatsapp.com", "x.com", "twitter.com", "linkedin.com",
    "reddit.com", "quora.com", "pinterest.com", "telegram.org", "discord.com", "snapchat.com",
    "spotify.com", "netflix.com", "primevideo.com", "hotstar.com", "jiocinema.com", "twitch.tv",
    "imdb.com", "wikipedia.org", "wikimedia.org", "bbc.com", "bbc.co.uk", "cnn.com",
    "nytimes.com", "theguardian.com", "reuters.com", "espn.com", "espncricinfo.com",
    "ndtv.com", "indiatimes.com", "hindustantimes.com", "thehindu.com", "indianexpress.com",
    # shopping, food, travel, payments (global + India)
    "amazon.com", "amazon.in", "flipkart.com", "myntra.com", "meesho.com", "nykaa.com",
    "ajio.com", "bigbasket.com", "snapdeal.com", "tatacliq.com", "croma.com", "reliancedigital.in",
    "zomato.com", "swiggy.com", "blinkit.com", "zeptonow.com", "makemytrip.com", "goibibo.com",
    "cleartrip.com", "redbus.in", "uber.com", "olacabs.com", "booking.com", "airbnb.com",
    "paypal.com", "paytm.com", "phonepe.com", "razorpay.com", "stripe.com", "visa.com",
    "mastercard.com", "npci.org.in", "airtel.in", "jio.com", "myvi.in", "bsnl.co.in",
    # Indian banks and financial regulators
    "onlinesbi.sbi", "sbi.co.in", "sbicard.com", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
    "idfcfirstbank.com", "yesbank.in", "indusind.com", "bankofindia.co.in", "rbi.org.in",
    "sebi.gov.in", "nseindia.com", "bseindia.com", "zerodha.com", "groww.in", "licindia.in",
    # Indian government
    "india.gov.in", "uidai.gov.in", "incometax.gov.in", "gst.gov.in", "digilocker.gov.in",
    "mygov.in", "epfindia.gov.in", "passportindia.gov.in", "parivahan.gov.in", "irctc.co.in",
    "indianrail.gov.in", "umang.gov.in", "eci.gov.in", "cowin.gov.in", "swayam.gov.in",
    "nta.ac.in", "ugc.gov.in", "aicte-india.org",
    # education
    "mitaoe.ac.in", "nptel.ac.in", "iitb.ac.in", "iitm.ac.in", "iitd.ac.in", "iisc.ac.in",
    "unipune.ac.in", "coursera.org", "udemy.com", "edx.org", "khanacademy.org", "mit.edu",
    "stanford.edu", "harvard.edu", "nature.com", "springer.com", "ieee.org", "acm.org",
    "arxiv.org", "researchgate.net", "uci.edu",
})

#: Hosts where anyone can publish content -> never trusted (suffix match on the host).
UNTRUSTED_HOST_SUFFIXES: tuple[str, ...] = (
    "sites.google.com", "drive.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "googleusercontent.com", "web.app", "firebaseapp.com", "github.io", "githubusercontent.com",
    "gist.github.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "blogspot.com",
    "weebly.com", "weeblysite.com", "wixsite.com", "000webhostapp.com", "forms.office.com",
    "sharepoint.com", "onedrive.live.com", "1drv.ms", "forms.gle", "glitch.me", "repl.co",
    "replit.app", "onrender.com", "herokuapp.com", "azurewebsites.net", "amazonaws.com",
    "cloudfront.net", "r2.dev", "notion.site", "gitbook.io", "canva.site", "my.canva.site",
    "framer.app", "framer.website", "webflow.io", "godaddysites.com", "square.site", "wordpress.com",
    # seen among the Step 2 OpenPhish misses
    "backblazeb2.com", "sharemyhtml.com",
)

#: (host suffix, path regex) pairs that are user content or open redirects on trusted domains.
UNTRUSTED_PATHS: tuple[tuple[str, str], ...] = (
    ("docs.google.com", r"^/forms"),               # Google Forms: anyone can build a login form
    ("google.com", r"^/url"),                      # google.com/url?q=... open redirect
    ("google.co.in", r"^/url"),
    ("google.com", r"^/amp/"),                     # AMP proxy of arbitrary pages
    ("youtube.com", r"^/redirect"),
    ("facebook.com", r"^/l\.php"), ("l.facebook.com", r""), ("l.instagram.com", r""),
    ("linkedin.com", r"^/redir"),
    ("github.com", r"/releases/download/"),        # arbitrary binaries uploaded by any user
)

_IPFS_RE = re.compile(r"(^|\.)ipfs\.|ipfs\.io|/ipfs/|dweb\.link|\.ipns\.", re.IGNORECASE)


def _host_matches(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def check_trusted(url: str) -> tuple[bool, str]:
    """(trusted, reason). Trusted only if the exact registered domain is listed
    AND the host/path is not a user-content or redirect location."""
    p = parse_url(url)
    host, rd = p.host, p.registered_domain
    if not host or p.is_ip:
        return False, "no domain"
    if _IPFS_RE.search(host + p.path):
        return False, "IPFS gateway (user content)"
    for suf in UNTRUSTED_HOST_SUFFIXES:
        if _host_matches(host, suf):
            return False, f"user-content host ({suf})"
    for suf, rx in UNTRUSTED_PATHS:
        if _host_matches(host, suf) and re.search(rx, p.path or "/"):
            return False, f"user content / redirect path on {suf}"
    if rd in TRUSTED_DOMAINS:
        return True, f"trusted domain ({rd})"
    return False, "not on the trusted list"

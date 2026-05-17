from __future__ import annotations

import re
from urllib.parse import urlparse

_RE_URL = re.compile(r'https?://[^\s"<>]+')
_RE_CONTRACT = re.compile(r"0x[a-fA-F0-9]{40}")
_RE_CHAINSCAN_TX = re.compile(r"https://chainscan\.0g\.ai/tx/(?:0x)?[a-fA-F0-9]{64}")
_RE_IS_SUBMIT = re.compile(r'"isSubmit"\s*:\s*(true|false)')
_RE_IS_SUBMIT_ESCAPED = re.compile(r'\\"isSubmit\\"\s*:\s*(true|false)')


def normalize_x_link(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        # HackQuest sometimes emits `https://<username>/status/<id>` (no real host).
        if parsed.netloc and "." not in parsed.netloc and "/status/" in parsed.path:
            return f"https://x.com/{parsed.netloc}{parsed.path}"
        if "x.com" in parsed.netloc or "twitter.com" in parsed.netloc:
            return raw.replace("http://", "https://", 1)
        return raw.replace("http://", "https://", 1)
    # HackQuest sometimes renders just `user/status/<id>` as a relative-ish link.
    return f"https://x.com/{raw.lstrip('/')}"


def parse_hackquest_project_html(
    html: str,
) -> tuple[str | None, str | None, str | None, list[str], list[str]]:
    open_source_link: str | None = None
    mvp_link: str | None = None
    x_link: str | None = None
    x_status_link: str | None = None
    x_profile_link: str | None = None

    hrefs = re.findall(r'href="([^"]+)"', html)
    for href in hrefs:
        if open_source_link is None and "github.com/" in href:
            open_source_link = href
        if mvp_link is None and ("github.io/" in href or "vercel.app" in href):
            mvp_link = href
        if "x.com/" in href or re.match(r"^[^/]+/status/\d+$", href) or "status/" in href:
            normalized = normalize_x_link(href)
            if "/status/" in normalized:
                x_status_link = x_status_link or normalized
            elif "x.com/" in normalized or "twitter.com/" in normalized:
                x_profile_link = x_profile_link or normalized

    x_link = x_status_link or x_profile_link

    if open_source_link is None or mvp_link is None or x_link is None:
        x_status_link = x_link if x_link and "/status/" in x_link else None
        x_profile_link = x_link if x_link and "/status/" not in x_link else None
        for url in _RE_URL.findall(html):
            if open_source_link is None and "github.com/" in url:
                open_source_link = url
            if mvp_link is None and ("github.io/" in url or "vercel.app" in url):
                mvp_link = url
            if "x.com/" in url or "twitter.com/" in url:
                normalized = normalize_x_link(url)
                if "/status/" in normalized:
                    x_status_link = x_status_link or normalized
                else:
                    x_profile_link = x_profile_link or normalized
        x_link = x_status_link or x_profile_link

    contract_addresses = sorted(set(_RE_CONTRACT.findall(html)), key=str.lower)
    chainscan_tx_urls = sorted(set(_RE_CHAINSCAN_TX.findall(html)))
    return open_source_link, mvp_link, x_link, contract_addresses, chainscan_tx_urls


def parse_hackquest_is_submit(html: str) -> bool | None:
    for regex in (_RE_IS_SUBMIT, _RE_IS_SUBMIT_ESCAPED):
        match = regex.search(html)
        if match:
            return match.group(1) == "true"
    return None

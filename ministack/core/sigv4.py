"""
AWS Signature Version 4 (SigV4) — sign and verify.

Implements the SigV4 signing algorithm as described in:
https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

Used by ``app.py`` to validate incoming requests when ``IAM_ENFORCE=1``.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re

logger = logging.getLogger("sigv4")

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_AUTH_RE = re.compile(
    r"AWS4-HMAC-SHA256\s+"
    r"Credential=(?P<access_key>[^/]+)/(?P<date>[^/]+)/(?P<region>[^/]+)/"
    r"(?P<service>[^/]+)/aws4_request,\s*"
    r"SignedHeaders=(?P<signed_headers>[^,]+(?:,[^,]+)*),\s*"
    r"Signature=(?P<signature>[0-9a-f]{64})",
    re.IGNORECASE,
)


def parse_authorization(auth_header: str) -> dict | None:
    """Parse an AWS SigV4 Authorization header.

    Returns None if the header doesn't match.
    """
    m = _AUTH_RE.search(auth_header)
    if not m:
        return None
    return {
        "access_key": m.group("access_key"),
        "date": m.group("date"),
        "region": m.group("region"),
        "service": m.group("service"),
        "signed_headers": m.group("signed_headers").lower(),
        "signature": m.group("signature"),
    }


# ---------------------------------------------------------------------------
# Signing key derivation
# ---------------------------------------------------------------------------


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hex(data: bytes) -> str:
    return data.hex()


def derive_signing_key(secret_access_key: str, date: str, region: str, service: str) -> bytes:
    """Derive the SigV4 signing key.

    kDate    = HMAC("AWS4" + secret, date)
    kRegion  = HMAC(kDate, region)
    kService = HMAC(kRegion, service)
    kSigning = HMAC(kService, "aws4_request")
    """
    k_secret = ("AWS4" + secret_access_key).encode("utf-8")
    k_date = _sign(k_secret, date)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    return k_signing


# ---------------------------------------------------------------------------
# String to sign
# ---------------------------------------------------------------------------


def _canonical_headers(headers: dict, signed_headers: str) -> str:
    """Build the canonical headers portion."""
    parts = []
    for name in sorted(signed_headers.split(";")):
        hname = name.strip().lower()
        hvalue = headers.get(hname, "")
        # Normalize whitespace in header values
        hvalue = " ".join(hvalue.split())
        parts.append(f"{hname}:{hvalue}")
    return "\n".join(parts) + "\n"


def _signed_headers_str(signed_headers: str) -> str:
    return ";".join(sorted(h.strip().lower() for h in signed_headers.split(";")))


def _canonical_request(method: str, path: str, query_string: str,
                       headers: dict, signed_headers: str,
                       body: bytes) -> str:
    """Build the canonical request for SigV4."""
    canon_headers = _canonical_headers(headers, signed_headers)
    signed_str = _signed_headers_str(signed_headers)
    payload_hash = _hex(_sha256(body or b""))

    return (
        f"{method.upper()}\n"
        f"{path}\n"
        f"{query_string}\n"
        f"{canon_headers}\n"
        f"{signed_str}\n"
        f"{payload_hash}"
    )


def _string_to_sign(amz_date: str, date: str, region: str, service: str,
                    canonical_request: str) -> str:
    """Build the string to sign.

    amz_date is the full x-amz-date value (e.g. 20260601T235810Z).
    date is just the YYYYMMDD portion.
    """
    cr_hash = _hex(_sha256(canonical_request.encode("utf-8")))
    return (
        f"AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{date}/{region}/{service}/aws4_request\n"
        f"{cr_hash}"
    )


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------


def compute_signature(secret_access_key: str, date: str, region: str,
                      service: str, method: str, path: str,
                      query_string: str, headers: dict,
                      signed_headers: str, body: bytes,
                      amz_date: str = "") -> str:
    """Compute the SigV4 signature for a request.

    date: YYYYMMDD (from credential scope).
    amz_date: full x-amz-date header value (e.g. 20260601T235810Z).
    """
    signing_key = derive_signing_key(secret_access_key, date, region, service)
    cr = _canonical_request(method, path, query_string, headers, signed_headers, body)
    sts = _string_to_sign(amz_date, date, region, service, cr)
    return _hex(_sign(signing_key, sts))


def verify_signature(secret_access_key: str, auth: dict,
                     method: str, path: str,
                     query_string: str, headers: dict,
                     body: bytes) -> bool:
    """Verify a SigV4 signature against a request."""
    amz_date = headers.get("x-amz-date", "")
    expected = compute_signature(
        secret_access_key,
        auth["date"], auth["region"], auth["service"],
        method, path, query_string, headers,
        auth["signed_headers"], body,
        amz_date=amz_date,
    )
    return hmac.compare_digest(expected, auth["signature"])

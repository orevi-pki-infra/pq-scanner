from __future__ import annotations

from typing import Any, Dict, List, Optional


_TLS_VERSION_ORDER = {
    "SSL2": 0,
    "SSL3": 1,
    "TLS1.0": 2,
    "TLS1.1": 3,
    "TLS1.2": 4,
    "TLS1.3": 5,
}


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _min_tls_version(versions: List[str]) -> Optional[str]:
    known = [v for v in versions if v in _TLS_VERSION_ORDER]
    if not known:
        return None
    return sorted(known, key=lambda v: _TLS_VERSION_ORDER[v])[0]


def _max_tls_version(versions: List[str]) -> Optional[str]:
    known = [v for v in versions if v in _TLS_VERSION_ORDER]
    if not known:
        return None
    return sorted(known, key=lambda v: _TLS_VERSION_ORDER[v])[-1]


def summarize_tls_posture(observation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compact descriptive posture (not a second scoring model):
    - TLS protocol posture (versions)
    - KEX / FS signals from cipher suites
    - Leaf cert crypto posture (key type/size, sig algorithm)
    """

    tls = observation.get("tls", {}) or {}
    pki = observation.get("pki", {}) or {}
    leaf = pki.get("leaf", {}) or {}

    versions = [str(v) for v in _as_list(tls.get("versions_supported"))]
    suites = [str(s) for s in _as_list(tls.get("cipher_suites_offered"))]

    supports_tls13 = "TLS1.3" in versions
    supports_tls12 = "TLS1.2" in versions

    # Lightweight heuristics (good enough for v0.1)
    has_rsa_kex = any(s.startswith("TLS_RSA_") for s in suites)
    has_ecdhe = any("ECDHE" in s for s in suites)

    sig_alg = str(leaf.get("signature_algorithm") or "")
    pub_type = str(leaf.get("public_key_type") or "")
    pub_bits = leaf.get("public_key_bits")

    pq_signal = "unknown"
    if pub_type.upper() == "RSA" and isinstance(pub_bits, int):
        if pub_bits >= 3072:
            pq_signal = "rsa_3072_plus"
        elif pub_bits >= 2048:
            pq_signal = "rsa_2048"
        else:
            pq_signal = "rsa_weak"
    elif pub_type.upper() in {"EC", "ECDSA", "ECC"}:
        pq_signal = "ecc"

    sig_legacy = "sha1" in sig_alg.lower() or "md5" in sig_alg.lower()

    return {
        "tls": {
            "versions_supported": versions,
            "min_version": _min_tls_version(versions),
            "max_version": _max_tls_version(versions),
            "supports_tls12": supports_tls12,
            "supports_tls13": supports_tls13,
            "cipher_suites_offered_count": len(suites),
            "signals": {
                "has_rsa_key_exchange": has_rsa_kex,
                "has_forward_secrecy_candidate": has_ecdhe or supports_tls13,
            },
        },
        "pki_leaf": {
            "public_key_type": pub_type,
            "public_key_bits": pub_bits,
            "signature_algorithm": sig_alg,
            "signature_legacy": sig_legacy,
            "days_to_expiry": leaf.get("days_to_expiry"),
            "not_after": leaf.get("not_after"),
            "fingerprint_sha256": leaf.get("fingerprint_sha256"),
        },
        "pq_signal": pq_signal,
    }


def summarize_posture(observation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    surface = observation.get("surface")
    if surface == "tls":
        return summarize_tls_posture(observation)
    return None

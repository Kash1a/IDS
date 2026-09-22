import re
from urllib.parse import unquote
from ids.alert.alert import alert_detect_sqli
import json

def normalize_payload(payload):
    """Chuẩn hóa payload để phát hiện mẫu tấn công."""
    if not payload:
        return ""
    payload = str(payload)

    # Decode URL 3 lần
    for _ in range(3):
        decoded = unquote(payload)
        if decoded == payload:
            break
        payload = decoded

    payload = payload.lower()
    payload = re.sub(r"\s+", " ", payload)
    return payload


def detect_sqli(session, rules):
    http = session.get("http")
    if not http or not http.get("is_http"):
        return
    SQLI_PATTERNS = rules.get("SQLI_PATTERNS", [])

    transactions = http.get("transactions", [])
    if not transactions:
        return
    transaction = transactions[-1]

    uri = (transaction.get("request") or {}).get("uri", "") or ""
    body = (transaction.get("request") or {}).get("body", "") or ""

    payload = normalize_payload(uri + " " + body)   # <-- gọi hàm normalize

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            network = session.get("network", {})
            src_ip = network.get("src_ip", "")
            alert_detect_sqli(src_ip, payload)
            return
    return
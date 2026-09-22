from ids.alert.alert import alert_detect_xss
import json
import re

def normalize_payload(payload):
    """
    Chuẩn hóa payload để dễ dàng phát hiện các mẫu tấn công.
    """
    if not payload:
        return ""
    payload = str(payload)
    from urllib.parse import unquote
    #Decode URL-encoded characters
    for _ in range(3):
        payload = unquote(payload)
    #Chuyển payload về chữ thường
    payload = payload.lower()
    #Loai bo khoang trang
    payload = re.sub(r"\s+", " ", payload)
    return payload

def detect_xss(session, rules):
    http = session.get("http")
    if not http or not http.get("is_http"):
        return
    XSS_PATTERNS = rules.get("XSS_PATTERNS", [])

    transactions = http.get("transactions", [])
    if not transactions:
        return
    transaction = transactions[-1]

    uri = (transaction.get("request") or {}).get("uri", "") or ""
    body = (transaction.get("request") or {}).get("body", "") or ""

    payload = normalize_payload(uri + " " + body)   # <-- gọi hàm normalize đã định nghĩa

    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            network = session.get("network", {})
            src_ip = network.get("src_ip", "")
            alert_detect_xss(src_ip, payload)
            return
    return
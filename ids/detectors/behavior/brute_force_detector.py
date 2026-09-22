import json
from ids.alert.alert import  alert_detect_brute_force
def detect_brute_force(sessions,rules):

    MAX_FAILED_LOGINS = rules.get("MAX_FAILED_LOGINS",0)
    REQUEST_RATE_THRESHOLD = rules.get("REQUEST_RATE_THRESHOLD",0)


    login_failed_count = 0

    failed_logins ={} # Lưu số lần thất bại theo từng IP nguồn

    for session in sessions:
        timestamp = session.get("timestamp", {})
        network = session.get("network", {})
        http = session.get("http", {})
        transactions = http.get("transactions", [])
        src_ip = network.get("src_ip", "")

        if http.get("is_http") != True:
            continue

        for transaction in transactions:
            request = transaction.get("request", {})
            response = transaction.get("response", {})
            method = request.get("method", "")
            uri = request.get("uri", "")
            status_code = response.get("status_code", 0)

            # Kiểm tra nếu là hành động POST /login và trả về lỗi 401 (Unauthorized)
            if method == "POST" and "/login" in uri:
                if status_code == 401:
                    login_failed_count += 1
                    
                    if src_ip not in failed_logins:
                        failed_logins[src_ip] = 0
                    failed_logins[src_ip] += 1

    # --- CÁC KIỂM TRA NÀY PHẢI ĐẶT NGOÀI VÒNG LẶP FOR (để duyệt xong mới kết luận) ---
    
    # 1. Kiểm tra xem có IP nào vượt ngưỡng max failed logins không
    detected_ips = []
    for ip_src, count in failed_logins.items():
        if count > MAX_FAILED_LOGINS:
            detected_ips.append(ip_src)

    if detected_ips:
        for ip in detected_ips:
            evidence = "IP: " + ip + "exceed failed threshold"
            alert_detect_brute_force(evidence)

    # 2. Kiểm tra tổng tốc độ request lỗi toàn cục
    if login_failed_count / 10 > REQUEST_RATE_THRESHOLD:
        evidence = "Exceed failed login rate"
        alert_detect_brute_force(evidence)
        
    return
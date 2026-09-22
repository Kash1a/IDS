from scapy.all import IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply,  Raw
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
import re
import json
HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS"
}

HTTP_RESPONSE_RE = re.compile(r"^HTTP/\d\.\d\s+(\d{3})\s*(.*)$")

# Lay timestamp

def get_timestamp(packet):
    if hasattr(packet, "time"):
        return float(packet.time)

    return datetime.now(timezone.utc).timestamp()

# Lay IP

def get_ip_layer(packet):
    if IP in packet:
        return packet[IP]

    if IPv6 in packet:
        return packet[IPv6]

    return None

# Lay giao thuc

def get_protocol(packet):
    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"
    
    if ICMP in packet:
        return "ICMP"
 
    if ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
        return "ICMPv6"

    return None

# HTTP Request

def extract_http_request(payload):
    """
    GET /login?id=1 HTTP/1.1
    Host: 192.168.10.20
    User-Agent: Mozilla/5.0
    """

    result = {
        "is_http": False,
        "type": "",
        "transactions": [
            {
                "request": {
                    "method": "",
                    "host": "",
                    "uri": "",
                    "version": "",

                    "body": "",

                    "payload": {
                        "length": 0,
                        "parameter_count": 0,
                        "special_character_count": 0,
            		    "encoded_character_count": 0
                    }
                },

                "response": {
                    "status_code": 0,
                    "content_length": 0
                }
            }
        ]
    }

    if not payload:
        return result

    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return result

    lines = text.split("\r\n")

    if not lines:
        return result

    # HTTP Request Line

    request_line = lines[0].split()

    uri = ""

    if len(request_line) >= 3:
        method = request_line[0]
        uri = request_line[1]
        version = request_line[2]

        if method in HTTP_METHODS and version.startswith("HTTP/"):
            result["is_http"] = True
            result["type"] = "request"
            result["transactions"][0]["request"]["method"] = method
            result["transactions"][0]["request"]["uri"] = uri
            result["transactions"][0]["request"]["version"] = version

    # Khong phai HTTP request

    if not result["is_http"]:
        return result

    # host

    headers = _parse_headers(lines[1:])

    result["transactions"][0]["request"]["host"] = headers.get("host", "")

    # HTTP Body

    body = ""

    if "\r\n\r\n" in text:
        body = text.split("\r\n\r\n", 1)[1]

    result["transactions"][0]["request"]["body"] = body

    # Parameters/Payload

    uri_without_fragment = uri.split("#", 1)[0]

    parsed = urlparse(uri_without_fragment)

    query_params = parse_qs(parsed.query)

    parameter_count = len(query_params)

    if body:
        body_params = parse_qs(body)
        parameter_count += len(body_params)

    result["transactions"][0]["request"]["payload"]["length"] = len(parsed.query) + len(body)
    result["transactions"][0]["request"]["payload"]["parameter_count"] = parameter_count

    # Special characters

    special_chars = r"""'";<>(){}[]=-"""

    special_count = 0
    for c in (uri + body):
        if (c in special_chars):
            special_count += 1

    result["transactions"][0]["request"]["payload"]["special_character_count"] = special_count

    # URL encoded characters

    encoded = re.findall(r"%[0-9a-fA-F]{2}", uri + body)

    result["transactions"][0]["request"]["payload"]["encoded_character_count"] = len(encoded)

    return result

# HTTP Response

def extract_http_response(payload):

    """
    HTTP/1.1 200 OK
    Content-Type: text/html
    Content-Length: 512
    """

    result = {
        "is_http": False,
        "type": "",
        "transactions": [
            {
                "request": {
                    "method": "",
                    "host": "",
                    "uri": "",
                    "version": "",

                    "body": "",

                    "payload": {
                        "length": 0,
                        "parameter_count": 0,
                        "special_character_count": 0,
            		    "encoded_character_count": 0
                    }
                },

                "response": {
                    "status_code": 0,
                    "content_length": 0
                }
            }
        ]
    }

    if not payload:
        return result

    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return result

    lines = text.split("\r\n")

    if not lines:
        return result

    match = HTTP_RESPONSE_RE.match(lines[0].strip())

    if not match:
        return result

    result["is_http"] = True
    result["type"] = "response"
    result["transactions"][0]["request"]["version"] = lines[0].split()[0]
    result["transactions"][0]["response"]["status_code"] = int(match.group(1))

    # Body

    body = ""
    
    if "\r\n\r\n" in text:
        body = text.split("\r\n\r\n", 1)[1]
    result["transactions"][0]["response"]["content_length"] = len(body.encode("utf-8"))

    return result

def extract_http(payload):

    request = extract_http_request(payload)
    if request["is_http"]:
        return request

    response = extract_http_response(payload)
    if response["is_http"]:
        return response

    return request # Khong phai -> giu cau truc mac dinh
        

#=====================
def _parse_headers(lines):
    headers = {}

    for line in lines:
        if not line:
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    return headers

def parse_packet(packet):

    ip_layer = get_ip_layer(packet)
    if ip_layer is None:
        return None

    protocol = get_protocol(packet)
    if protocol is None:
        return None

    timestamp = get_timestamp(packet)

    packet_length = len(packet)

    result = {
        "timestamp": timestamp,

        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,

        "src_port": 0,
        "dst_port": 0,

        "protocol": protocol,

        "packet_length": packet_length,

        "tcp_flags": "",

        "syn": 0,
        "syn_ack": 0,
        "ack": 0,
        "fin": 0,
        "rst": 0,
        "psh": 0,

        "payload": b"",

        "http": None
    }

    # TCP

    if TCP in packet:

        tcp = packet[TCP]

        result["src_port"] = tcp.sport
        result["dst_port"] = tcp.dport

        flags = tcp.flags

        result["tcp_flags"] = str(flags)

        # SYN
        if flags & 0x02:
            result["syn"] = 1

        # SYN + ACK
        if (flags & 0x02) and (flags & 0x10):
            result["syn_ack"] = 1

        # ACK
        if flags & 0x10:
            result["ack"] = 1

        # FIN
        if flags & 0x01:
            result["fin"] = 1

        # RST
        if flags & 0x04:
            result["rst"] = 1

        # PSH
        if flags & 0x08:
            result["psh"] = 1



    # UDP

    elif UDP in packet:

        udp = packet[UDP]

        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport

    # Raw payload

    if Raw in packet:

        raw_data = bytes(packet[Raw].load)

        result["payload"] = raw_data

        # HTTP (request hoac response), chi ap dung cho TCP
        if TCP in packet:

            http = extract_http(raw_data)

            if http["is_http"]:
                result["http"] = http

    return result
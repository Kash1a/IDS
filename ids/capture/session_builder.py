import math
from collections import defaultdict
from datetime import datetime, timezone

class SessionBuilder:

    def __init__(self, session_timeout=120):

        # session_id -> session dict
        self.sessions = {}

        self._active_by_flow = {}

        self.session_counter = 0

        self.session_timeout = session_timeout

    # Session ID

    def _new_session_id(self):
        self.session_counter += 1

        return f"S{self.session_counter:03d}"

    # Flow key

    def _get_flow_key(self, packet):

        endpoint1 = (
            packet["src_ip"],
            packet["src_port"]
        )

        endpoint2 = (
            packet["dst_ip"],
            packet["dst_port"]
        )

        endpoints = sorted([
            endpoint1,
            endpoint2
        ])

        return (
            endpoints[0],
            endpoints[1],
            packet["protocol"]
        )

    # Tao session

    def _create_session(self, packet):

        session_id = self._new_session_id()

        timestamp = packet["timestamp"]

        session = {
            "session_id": session_id,

            "timestamp": {
                "start": timestamp,
                "end": timestamp,
                "duration": 0
            },

            "network": {
                "src_ip": packet["src_ip"],
                "dst_ip": packet["dst_ip"],

                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],

                "protocol": packet["protocol"]
            },

            "flag": {
                "syn": 0,
                "syn_ack": 0,
                "ack": 0,
                "fin": 0,
                "rst": 0,
                "psh": 0,
                "ack_count": 0
            },

            "packets": {
                "total": 0,

                "forward": {
                    "count": 0,
                    "bytes": 0
                },

                "backward": {
                    "count": 0,
                    "bytes": 0
                }
            },

            "flow": {
                "total_bytes": 0,
                "bytes_per_second": 0,
                "packets_per_second": 0,

                "packet_length": {
                    "min": None,
                    "max": None,
                    "mean": 0,
                    "std": 0
                },

                "iat": {
                    "mean": 0,
                    "std": 0,
                    "min": None,
                    "max": None
                }
            },

            "http": {
                "is_http": False,

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
            },

            "connection": {
                "request_count": 0,
                "response_count": 0,
                "status_code": 0,
                "_state": "active"  # active | closed | timed_out
            },

            # Internal fields (không xuất ra ngoài get_sessions())
            "_packet_lengths": [],
            "_timestamps": [],
            "_forward_key": (
                packet["src_ip"],
                packet["src_port"]
            ),
            "_last_seen": timestamp,
            "_fin_seen": set(),
            "_closed": False
        }

        return session

    # Update TCP

    def _update_tcp(self, session, packet):

        flag = session["flag"]

        flag["syn"] += packet["syn"]
        flag["syn_ack"] += packet["syn_ack"]
        flag["ack"] += packet["ack"]
        flag["fin"] += packet["fin"]
        flag["rst"] += packet["rst"]
        flag["psh"] += packet["psh"]

        if packet["ack"]:
            flag["ack_count"] += 1

        # Trang thai ket noi

        if packet["rst"]:
            session["_closed"] = True
            session["connection"]["_state"] = "closed"

        if packet["fin"]:

            direction = (
                packet["src_ip"],
                packet["src_port"]
            )

            session["_fin_seen"].add(direction)

            # Hoan tat khi ca 2 chieu gui FIN
            if len(session["_fin_seen"]) >= 2:
                session["_closed"] = True
                session["connection"]["_state"] = "closed"

    # Forward / Backward

    def _update_direction(self, session, packet):

        packet_direction = ( 
            packet["src_ip"],
            packet["src_port"]
        )

        if packet_direction == session["_forward_key"]:

            direction = "forward"

        else:
            direction = "backward"

        session["packets"][direction]["count"] += 1

        session["packets"][direction]["bytes"] += \
            packet["packet_length"]

    # HTTP

    def _update_http(self, session, packet):

        http = packet.get("http")
        
        if not http or not http.get("is_http"):
            return

        session["http"]["is_http"] = True
        transactions = session["http"]["transactions"]
        packet_transaction = http["transactions"][0]

        if http.get("type") == "request":
            # Nếu transaction cuối vẫn còn "trống" (chưa có request thật) thì dùng lại,
            # ngược lại tạo transaction mới cho request tiếp theo trong cùng session
            if transactions and transactions[-1]["request"]["method"] == "" \
            and transactions[-1]["response"]["status_code"] == 0:
                transactions[-1]["request"] = packet_transaction["request"]
            else:
                transactions.append({
                    "request": packet_transaction["request"],
                    "response": {"status_code": 0, "content_length": 0}
                })
            session["connection"]["request_count"] += 1

        elif http.get("type") == "response":
            if transactions:
                transactions[-1]["response"] = packet_transaction["response"]
            session["connection"]["response_count"] += 1

    # Add packet to session

    def add_packet(self, packet):

        flow_key = self._get_flow_key(packet)

        timestamp = packet["timestamp"]

        session = self._get_or_create_session(flow_key, timestamp, packet)

        # Timestamp / last_seen

        session["timestamp"]["end"] = timestamp
        session["_last_seen"] = timestamp

        session["_timestamps"].append(timestamp)

        # Duration

        duration = (
            session["timestamp"]["end"]
            - session["timestamp"]["start"]
        )

        session["timestamp"]["duration"] = max(0, duration)

        # Packets: total
        
        session["packets"]["total"] += 1

        # Packet_length

        session["_packet_lengths"].append(packet["packet_length"])

        # Flow : total_bytes

        session["flow"]["total_bytes"] += packet["packet_length"]

        # Direction

        self._update_direction(session,packet)

        # TCP

        if packet["protocol"] == "TCP":

            self._update_tcp(session, packet)

        # HTTP

        self._update_http(session, packet)

        # Flow
        self._update_statistics(session)

        return session

    # ==================

    def _get_or_create_session(self, flow_key, timestamp, packet):

        session_id = self._active_by_flow.get(flow_key)

        session = self.sessions.get(session_id) if session_id else None

        needs_new_session = (
            session is None
            or session["_closed"]
            or (timestamp - session["_last_seen"]) > self.session_timeout
        )

        if needs_new_session:

            if session is not None and not session["_closed"]:
                session["connection"]["_state"] = "timed_out"
                session["_closed"] = True

            session = self._create_session(packet)

            self.sessions[session["session_id"]] = session
            self._active_by_flow[flow_key] = session["session_id"]

        return session

    # _update_statistics
    def _update_statistics(self, session):

        duration = session["timestamp"]["duration"]

        total_bytes = session["flow"]["total_bytes"]

        total_packets = session["packets"]["total"]

        # Bytes/Packets per second

        if duration > 0:

            session["flow"]["bytes_per_second"] = total_bytes / duration
            session["flow"]["packets_per_second"] = total_packets / duration

        else:

            session["flow"]["bytes_per_second"] = 0
            session["flow"]["packets_per_second"] = 0

        # Packet length

        lengths = session["_packet_lengths"]

        if lengths:

            mean = sum(lengths) / len(lengths) #Trung binh

            variance = sum(
                (x - mean) ** 2
                for x in lengths
            ) / len(lengths)

            session["flow"]["packet_length"] = {
                "min": min(lengths),
                "max": max(lengths),
                "mean": mean,
                "std": math.sqrt(variance) #std cho biet do dai packet thuong lech khoi mean khoang bao nhieu
            }

        # IAT: thoi gian giua 2 goi tin lien tiep

        timestamps = session["_timestamps"]

        if len(timestamps) >= 2:

            iats = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, len(timestamps))
            ]

            mean = sum(iats) / len(iats)

            variance = sum(
                (x - mean) ** 2
                for x in iats
            ) / len(iats)

            session["flow"]["iat"] = {

                "mean": mean,
                "std": math.sqrt(variance),
                "min": min(iats),
                "max": max(iats)
            }

    # Dong cac session qua session_timeout (Goi dinh ky)

    def close_expired_sessions(self, current_time=None):

        if current_time is None:
            current_time = datetime.now(timezone.utc).timestamp()

        expired_ids = []

        for session_id, session in self.sessions.items():

            if session["_closed"]:
                continue

            if (current_time - session["_last_seen"]) > self.session_timeout:

                session["_closed"] = True
                session["connection"]["_state"] = "timed_out"

                expired_ids.append(session_id)

        return expired_ids

    # Get session

    def get_sessions(self, only_closed=False):

        result = []

        for session in self.sessions.values():

            if only_closed and not session["_closed"]:
                continue

            clean_session = {
                key: value
                for key, value in session.items()
                if not key.startswith("_")
            }

            result.append(clean_session)

        return result

    # Xoa cac session da dong

    def clear_closed_sessions(self):

        closed_ids = [
            session_id
            for session_id, session in self.sessions.items()
            if session["_closed"]
        ]

        for session_id in closed_ids:
            del self.sessions[session_id]

        stale_flow_keys = [
            flow_key
            for flow_key, sid in self._active_by_flow.items()
            if sid in closed_ids
        ]

        for flow_key in stale_flow_keys:
            del self._active_by_flow[flow_key]

        return len(closed_ids)
import threading

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


class PacketSniffer(threading.Thread):
    """Scapyを使ってパケットをキャプチャするスレッド"""

    def __init__(self, iface_name, packet_callback, stop_event, bpf_filter=""):
        super().__init__(daemon=True)

        self.iface_name = iface_name
        self.packet_callback = packet_callback
        self.stop_event = stop_event
        self.bpf_filter = bpf_filter

    def _packet_handler(self, pkt):
        """1パケット受信時の処理"""

        if self.stop_event.is_set():
            return

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]

        src_ip = ip.src
        dst_ip = ip.dst

        src_mac = pkt.src if hasattr(pkt, "src") else ""
        dst_mac = pkt.dst if hasattr(pkt, "dst") else ""

        src_port = ""
        dst_port = ""
        protocol = str(ip.proto)

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            protocol = "TCP"

        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            protocol = "UDP"

        elif ip.proto == 1:
            protocol = "ICMP"

        packet_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
        }

        self.packet_callback(packet_info)

    def run(self):
        """キャプチャ開始"""

        try:
            sniff(
                iface=self.iface_name,
                prn=self._packet_handler,
                store=False,
                filter=self.bpf_filter or None,
                stop_filter=lambda pkt: self.stop_event.is_set(),
            )

        except Exception as e:
            self.packet_callback({
                "type": "error",
                "message": str(e),
            })

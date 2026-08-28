"""
SIH26153 — Real-Time Packet Capture Module

Captures live network traffic using scapy in promiscuous mode and converts
packets into the JSONL format expected by the anomaly detection pipeline.

Usage:
    # Capture on default interface
    python -m integration.packet_capture

    # Capture on specific interface for 60 seconds
    python -m integration.packet_capture --interface eth0 --timeout 60

    # Capture and write to specific file
    python -m integration.packet_capture --output data/live_packets.jsonl
"""

import argparse
import json
import logging
import os
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── TCP flag mapping (scapy hex → string) ─────────────────
# Scapy uses bitmask integers for flags; we map to the string
# format the existing anomaly detector expects.
TCP_FLAG_MAP = {
    0x01: "F",      # FIN
    0x02: "S",      # SYN
    0x04: "R",      # RST
    0x08: "P",      # PSH
    0x10: "A",      # ACK
    0x11: "FA",     # FIN+ACK
    0x12: "SA",     # SYN+ACK
    0x14: "RA",     # RST+ACK
    0x18: "PA",     # PSH+ACK
    0x10: "A",      # ACK (solo)
}


def _tcp_flags_to_string(flags_int: int) -> str:
    """Convert scapy TCP flags bitmask to human-readable string."""
    if flags_int == 0:
        return ""
    parts = []
    if flags_int & 0x01:
        parts.append("F")
    if flags_int & 0x02:
        parts.append("S")
    if flags_int & 0x04:
        parts.append("R")
    if flags_int & 0x08:
        parts.append("P")
    if flags_int & 0x10:
        parts.append("A")
    return "".join(parts) if parts else str(flags_int)


def _protocol_name(proto_num: int) -> str:
    """Map IP protocol number to name."""
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, f"PROTO-{proto_num}")


def packet_to_dict(pkt) -> Optional[Dict]:
    """
    Convert a scapy packet to the JSONL dict format used throughout the pipeline.

    Expected downstream fields:
        timestamp, src_ip, dst_ip, protocol, src_port, dst_port,
        flags, payload_size, ttl, total_length
    """
    try:
        if not pkt.haslayer("IP"):
            return None

        ip_layer = pkt["IP"]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = ip_layer.ttl
        proto_num = ip_layer.proto
        protocol = _protocol_name(proto_num)
        total_length = int(ip_layer.len) if hasattr(ip_layer, "len") else len(pkt)

        src_port = None
        dst_port = None
        flags = None
        payload_size = 0

        if protocol == "TCP" and pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            flags = _tcp_flags_to_string(int(tcp.flags))
            payload_size = len(tcp.payload)

        elif protocol == "UDP" and pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            payload_size = len(udp.payload)

        elif protocol == "ICMP" and pkt.haslayer("ICMP"):
            icmp = pkt["ICMP"]
            payload_size = len(icmp.payload)

        # Use receive time as timestamp for accuracy
        ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")

        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
            "payload_size": payload_size,
            "ttl": ttl,
            "total_length": total_length,
        }
    except Exception as e:
        logger.debug(f"Failed to parse packet: {e}")
        return None


class PacketCapturer:
    """
    Real-time packet capturer using scapy.

    Runs in promiscuous mode and writes packets as JSONL.
    Can be used in two modes:
      1. Continuous — runs until stopped (via thread or signal)
      2. Timed — runs for a fixed duration then stops

    Requires root/admin privileges for promiscuous capture.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        output_file: str = "data/packets.jsonl",
        bpf_filter: Optional[str] = None,
        packet_callback: Optional[Callable[[Dict], None]] = None,
    ):
        """
        Args:
            interface: Network interface to capture on (None = default).
            output_file: Path to write captured packets (JSONL).
            bpf_filter: BPF filter string (e.g. "tcp port 22").
            packet_callback: Optional callback invoked for each captured packet dict.
        """
        self.interface = interface
        self.output_file = Path(output_file)
        self.bpf_filter = bpf_filter
        self.packet_callback = packet_callback

        self._capture = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._lock = threading.Lock()
        self._output_handle = None

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    @property
    def is_running(self) -> bool:
        return self._running

    def _open_output(self):
        """Open the output file for appending."""
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self._output_handle = open(self.output_file, "a", encoding="utf-8")

    def _close_output(self):
        """Close the output file handle."""
        if self._output_handle and not self._output_handle.closed:
            self._output_handle.close()
        self._output_handle = None

    def _process_packet(self, pkt):
        """Scapy sniff callback — convert and store each packet."""
        packet_dict = packet_to_dict(pkt)
        if packet_dict is None:
            return

        line = json.dumps(packet_dict) + "\n"

        with self._lock:
            self._packet_count += 1
            if self._output_handle and not self._output_handle.closed:
                self._output_handle.write(line)
                self._output_handle.flush()

        # Fire optional callback (e.g. for real-time anomaly detection)
        if self.packet_callback:
            try:
                self.packet_callback(packet_dict)
            except Exception as e:
                logger.error(f"Packet callback error: {e}")

    def start(self, timeout: Optional[int] = None, count: Optional[int] = None):
        """
        Start packet capture.

        Args:
            timeout: Stop after this many seconds (None = run forever).
            count: Stop after this many packets (None = unlimited).
        """
        if self._running:
            logger.warning("Capture already running")
            return

        from scapy.all import (
            Sniffer,
            conf,
            get_if_list,
        )

        # Auto-detect interface if not specified
        iface = self.interface
        if not iface:
            interfaces = get_if_list()
            if interfaces:
                iface = interfaces[0]
                logger.info(f"Auto-selected interface: {iface}")
            else:
                logger.error("No network interfaces found")
                raise RuntimeError("No network interfaces available")

        logger.info(
            f"Starting capture on {iface}"
            f"{' with filter: ' + self.bpf_filter if self.bpf_filter else ''}"
        )

        self._open_output()
        self._running = True

        try:
            self._capture = Sniffer(
                iface=iface,
                prn=self._process_packet,
                filter=self.bpf_filter,
                timeout=timeout,
                count=count or 0,
                store=False,
                promisc=True,
            )
            self._capture.start()
            logger.info(
                f"Capture started: iface={iface}, timeout={timeout}, "
                f"filter={self.bpf_filter}"
            )
        except PermissionError:
            self._running = False
            self._close_output()
            raise PermissionError(
                "Packet capture requires root/admin privileges. "
                "Run with: sudo python -m integration.packet_capture"
            )
        except Exception as e:
            self._running = False
            self._close_output()
            raise

    def stop(self):
        """Stop packet capture gracefully."""
        if not self._running:
            return

        self._running = False
        if self._capture:
            try:
                self._capture.stop()
            except Exception as e:
                logger.debug(f"Error stopping capture: {e}")
        self._close_output()
        logger.info(
            f"Capture stopped. {self._packet_count} packets written to {self.output_file}"
        )

    def start_background(
        self,
        timeout: Optional[int] = None,
        count: Optional[int] = None,
    ) -> threading.Thread:
        """
        Start capture in a background thread (non-blocking).

        Returns the thread so the caller can join() if needed.
        """
        if self._running:
            logger.warning("Capture already running")
            return self._thread

        def _run():
            try:
                self.start(timeout=timeout, count=count)
                # If timeout/count is set, wait for capture to finish
                if self._capture:
                    self._capture.join()
            except Exception as e:
                logger.error(f"Background capture error: {e}")
            finally:
                self._running = False
                self._close_output()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        logger.info("Background capture thread started")
        return self._thread

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def get_local_ip() -> str:
    """Get the local machine's primary IP address."""
    import socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def list_interfaces() -> List[str]:
    """List available network interfaces."""
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception:
        return []


def get_default_interface() -> Optional[str]:
    """Get the default network interface."""
    try:
        from scapy.all import conf
        return conf.iface
    except Exception:
        return None


# ── CLI Entry Point ────────────────────────────────────────

def main():
    """CLI interface for packet capture."""
    parser = argparse.ArgumentParser(
        description="SIH26153 — Real-Time Packet Capture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture on default interface (requires root)
  sudo python -m integration.packet_capture

  # Capture for 60 seconds
  sudo python -m integration.packet_capture --timeout 60

  # Capture only TCP traffic on port 80
  sudo python -m integration.packet_capture --filter "tcp port 80"

  # List available interfaces
  python -m integration.packet_capture --list-interfaces
        """,
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface (default: auto-detect)",
    )
    parser.add_argument(
        "--output", "-o",
        default="data/packets.jsonl",
        help="Output file (default: data/packets.jsonl)",
    )
    parser.add_argument(
        "--filter", "-f",
        default=None,
        help="BPF filter (e.g. 'tcp port 22', 'host 192.168.1.1')",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=None,
        help="Stop after N seconds (default: run until Ctrl+C)",
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=None,
        help="Stop after N packets",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.list_interfaces:
        interfaces = list_interfaces()
        default_iface = get_default_interface()
        local_ip = get_local_ip()

        print(f"\nLocal IP: {local_ip}")
        print(f"Default interface: {default_iface}\n")
        print("Available interfaces:")
        for iface in interfaces:
            marker = " ← default" if iface == default_iface else ""
            print(f"  - {iface}{marker}")
        print()
        return

    local_ip = get_local_ip()
    print(f"\n{'='*60}")
    print(f"  SIH26153 — Real-Time Packet Capture")
    print(f"{'='*60}")
    print(f"  Local IP:   {local_ip}")
    print(f"  Interface:  {args.interface or '(auto-detect)'}")
    print(f"  Output:     {args.output}")
    print(f"  Filter:     {args.filter or '(none)'}")
    print(f"  Timeout:    {args.timeout or '(Ctrl+C to stop)'}")
    print(f"{'='*60}\n")

    capturer = PacketCapturer(
        interface=args.interface,
        output_file=args.output,
        bpf_filter=args.filter,
    )

    try:
        capturer.start(timeout=args.timeout, count=args.count)

        # Wait for capture to finish (timeout or Ctrl+C)
        if capturer._capture:
            capturer._capture.join()

    except KeyboardInterrupt:
        print("\n\nStopping capture...")
    finally:
        capturer.stop()

    print(f"\nCapture complete: {capturer.packet_count} packets captured")
    print(f"Saved to: {capturer.output_file}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
NetShield AI — Local Windows PyShark Capture Agent

Captures live network packets locally using PyShark/TShark/Npcap on your Windows laptop,
extracts 78+ CICIDS2017 flow/packet features using NetShield AI's feature extractor,
and transmits telemetry securely via HTTPS API to the deployed Render backend (or local backend).

Usage:
    # Run in remote mode (streams telemetry to deployed Render backend)
    python capture_agent.py --mode remote

    # Run in local mode (streams to local backend http://localhost:8000)
    python capture_agent.py --mode local

    # Custom options
    python capture_agent.py --mode remote --url https://netshield-ai-h038.onrender.com --interface 4 --api-key YOUR_API_KEY
"""

import argparse
import json
import logging
import os
import shutil
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# Add backend directory to sys.path so we can import app modules directly
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.packet_feature_extractor import extract_features_from_packet
from app.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] NetShield-Agent: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("NetShieldAgent")


def discover_tshark(configured_path: str = None) -> str:
    """Find TShark executable on Windows host."""
    if configured_path and os.path.exists(configured_path):
        return configured_path

    env_paths = [os.getenv("NETSHIELD_TSHARK_PATH"), os.getenv("TSHARK_PATH")]
    for p in env_paths:
        if p and os.path.exists(p):
            return p

    candidates = [
        r"E:\Wireshark\tshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    which_path = shutil.which("tshark")
    if which_path:
        return which_path

    return None


def send_telemetry_payload(target_url: str, api_key: str, payload: dict) -> dict:
    """Send extracted packet feature dictionary to NetShield AI backend via HTTPS POST."""
    ingest_endpoint = target_url.rstrip("/") + "/api/v1/network/live-capture/ingest"
    data_bytes = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(ingest_endpoint, data=data_bytes, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("X-API-Key", api_key)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP Error {e.code} sending packet telemetry to {ingest_endpoint}: {e.reason}")
        return None
    except urllib.error.URLError as e:
        logger.error(f"Network error connecting to backend {ingest_endpoint}: {e.reason}")
        return None
    except Exception as e:
        logger.error(f"Failed to post telemetry: {e}")
        return None


def run_agent(mode: str, remote_url: str, api_key: str, interface: str, tshark_path: str, duration: int = 0):
    """Main capture loop running PyShark locally on Windows."""
    resolved_tshark = discover_tshark(tshark_path)
    if not resolved_tshark:
        logger.critical("TShark/Wireshark executable not found! Please install Wireshark & Npcap on Windows.")
        sys.exit(1)

    tshark_dir = os.path.dirname(resolved_tshark)
    if tshark_dir not in os.environ["PATH"]:
        os.environ["PATH"] += os.pathsep + tshark_dir

    if mode == "local":
        target_url = "http://localhost:8000"
    else:
        target_url = remote_url or settings.NETSHIELD_REMOTE_API_URL

    logger.info("=" * 65)
    logger.info(" NetShield AI — Local Windows PyShark Capture Agent")
    logger.info(f" Mode:                {mode.upper()}")
    logger.info(f" Target Backend:      {target_url}")
    logger.info(f" Network Interface:   {interface}")
    logger.info(f" TShark Path:         {resolved_tshark}")
    logger.info("=" * 65)

    try:
        import pyshark
    except ImportError:
        logger.critical("PyShark Python package is missing. Install with: pip install pyshark")
        sys.exit(1)

    logger.info(f"Initializing PyShark LiveCapture on interface '{interface}' ...")

    packet_count = 0
    start_time = time.time()

    try:
        capture = pyshark.LiveCapture(interface=str(interface), tshark_path=resolved_tshark)
        logger.info("PyShark capture active! Press Ctrl+C to stop.\n")

        for packet in capture.sniff_continuously():
            if duration > 0 and (time.time() - start_time > duration):
                logger.info(f"Capture duration of {duration}s reached. Stopping agent.")
                break

            try:
                feat_dict = extract_features_from_packet(packet)
                packet_count += 1

                src_ip = feat_dict.get("source_ip", "N/A")
                dst_ip = feat_dict.get("destination_ip", "N/A")
                proto = feat_dict.get("protocol", "TCP")

                logger.info(f"[{packet_count}] Captured packet {src_ip} -> {dst_ip} ({proto})")

                # Transmit extracted features to Render / Backend
                resp = send_telemetry_payload(target_url, api_key, feat_dict)
                if resp:
                    total_p = resp.get("packet_count", packet_count)
                    threats = resp.get("threats_detected", 0)
                    logger.info(f"   ✓ Ingested by Backend | Total Packets: {total_p} | Threats Detected: {threats}")
                else:
                    logger.warning("   ✗ Telemetry ingestion failed (retrying on next packet)")

            except KeyboardInterrupt:
                raise
            except Exception as exc:
                logger.warning(f"Error processing packet: {exc}")

    except KeyboardInterrupt:
        logger.info("\nAgent stopped by user.")
    except Exception as exc:
        logger.error(f"LiveCapture error: {exc}")
    finally:
        logger.info(f"Agent finished. Total packets processed: {packet_count}")


def main():
    parser = argparse.ArgumentParser(description="NetShield AI Local Windows PyShark Capture Agent")
    parser.add_argument(
        "--mode",
        choices=["local", "remote"],
        default=os.getenv("NETSHIELD_CAPTURE_MODE", "remote"),
        help="Capture mode ('remote' for Render backend, 'local' for localhost:8000)"
    )
    parser.add_argument(
        "--url",
        default=os.getenv("NETSHIELD_REMOTE_API_URL", settings.NETSHIELD_REMOTE_API_URL),
        help="Target backend URL (e.g. https://netshield-ai-h038.onrender.com)"
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("NETSHIELD_CAPTURE_API_KEY", settings.NETSHIELD_CAPTURE_API_KEY),
        help="API Key for telemetry ingestion"
    )
    parser.add_argument(
        "--interface",
        default=os.getenv("NETSHIELD_CAPTURE_INTERFACE", settings.NETSHIELD_CAPTURE_INTERFACE),
        help="Network interface index or name (e.g. '4')"
    )
    parser.add_argument(
        "--tshark-path",
        default=os.getenv("NETSHIELD_TSHARK_PATH", settings.NETSHIELD_TSHARK_PATH),
        help="Path to tshark.exe"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="Duration in seconds to run capture (0 for continuous)"
    )

    args = parser.parse_args()
    run_agent(
        mode=args.mode,
        remote_url=args.url,
        api_key=args.api_key,
        interface=args.interface,
        tshark_path=args.tshark_path,
        duration=args.duration
    )


if __name__ == "__main__":
    main()

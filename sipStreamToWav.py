#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path


def build_display_cmd(pcap, src_ip, src_port, dst_ip, dst_port, outfile):
    return (
        f"tshark -r {pcap} "
        f"-Y 'ip.src=={src_ip} && udp.srcport=={src_port} "
        f"&& ip.dst=={dst_ip} && udp.dstport=={dst_port} && rtp' "
        f"-T fields -e rtp.payload > {outfile}.hex"
    )


def extract_rtp_payload_to_raw(pcap, src_ip, src_port, dst_ip, dst_port, raw_file):
    cmd = [
        "tshark",
        "-r", pcap,
        "-Y", (
            f"ip.src=={src_ip} && udp.srcport=={src_port} "
            f"&& ip.dst=={dst_ip} && udp.dstport=={dst_port} && rtp"
        ),
        "-T", "fields",
        "-e", "rtp.payload",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Error running tshark:")
        print(result.stderr)
        return False

    
    hex_lines = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        hex_lines.append(line.replace(":", ""))

    hex_data = "".join(hex_lines)

    if not hex_data:
        print(f"No RTP payload found for stream -> {raw_file}")
        return False

    try:
        raw_bytes = bytes.fromhex(hex_data)
    except ValueError as e:
        print(f"Failed to decode hex for {raw_file}: {e}")
        return False

    with open(raw_file, "wb") as f:
        f.write(raw_bytes)

    return True


def convert_raw_to_wav(raw_file, wav_file, codec="pcmu"):
    codec = codec.lower()

    if codec in ("pcmu", "g711u", "g711ulaw", "mulaw"):
        ffmpeg_fmt = "mulaw"
    elif codec in ("pcma", "g711a", "alaw"):
        ffmpeg_fmt = "alaw"
    else:
        print(f"Unsupported codec hint: {codec}")
        return False

    cmd = [
        "ffmpeg",
        "-y",
        "-f", ffmpeg_fmt,
        "-ar", "8000",
        "-ac", "1",
        "-i", str(raw_file),
        str(wav_file),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Error running ffmpeg:")
        print(result.stderr)
        return False

    return True


def process_stream(name, pcap, src_ip, src_port, dst_ip, dst_port, codec="pcmu"):
    raw_file = Path(f"{name}.raw")
    wav_file = Path(f"{name}.wav")

    print(f"# {name}")
    print(build_display_cmd(pcap, src_ip, src_port, dst_ip, dst_port, name))
    print()

    ok = extract_rtp_payload_to_raw(
        pcap=pcap,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        raw_file=raw_file,
    )
    if not ok:
        print(f"Failed to extract {name}")
        return

    ok = convert_raw_to_wav(
        raw_file=raw_file,
        wav_file=wav_file,
        codec=codec,
    )
    if not ok:
        print(f"Failed to convert {name} to wav")
        return

    print(f"Created: {raw_file}")
    print(f"Created: {wav_file}")
    print()


def main():
    pcap = "call_and_rtp.pcap"

    # ===== 4 endpoints =====
    caller_ip = "90.204.96.95"
    caller_port = 49167

    asterisk_caller_ip = "10.154.0.3"
    asterisk_caller_port = 16728

    callee_ip = "90.204.96.95"
    callee_port = 54082

    asterisk_callee_ip = "10.154.0.3"
    asterisk_callee_port = 19984

    codec = "pcmu"   
    # =======================

    streams = [
        (
            "caller_to_asterisk_caller",
            caller_ip, caller_port,
            asterisk_caller_ip, asterisk_caller_port,
        ),
        (
            "asterisk_caller_to_caller",
            asterisk_caller_ip, asterisk_caller_port,
            caller_ip, caller_port,
        ),
        (
            "callee_to_asterisk_callee",
            callee_ip, callee_port,
            asterisk_callee_ip, asterisk_callee_port,
        ),
        (
            "asterisk_callee_to_callee",
            asterisk_callee_ip, asterisk_callee_port,
            callee_ip, callee_port,
        ),
    ]

    for name, src_ip, src_port, dst_ip, dst_port in streams:
        process_stream(
            name=name,
            pcap=pcap,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            codec=codec,
        )


if __name__ == "__main__":
    main()
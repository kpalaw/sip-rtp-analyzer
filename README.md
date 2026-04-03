# SIP RTP to WAV Analyzer

A Python tool to extract RTP audio streams from SIP calls and convert them into WAV files.

## Why this project?

This project demonstrates:

- Deep understanding of SIP and RTP
- Packet-level analysis using tshark
- Media extraction from raw RTP streams
- Practical VoIP debugging skills

## Features

- Parse SIP/SDP from pcap
- Identify RTP endpoints (caller, callee, Asterisk)
- Extract RTP payload using tshark
- Convert raw audio to WAV using ffmpeg
- Supports 4 RTP legs:
  - caller → asterisk
  - asterisk → caller
  - callee → asterisk
  - asterisk → callee

## Requirements

- Python 3
- tshark
- ffmpeg

Install tshark:

```bash
sudo apt install tshark
```

Install ffmpeg:
```bash
sudo apt install ffmpeg
```

Usage
```bash
python3 sipStreamToWav.py
```

## SIP Transport Support

At present, the tool supports SIP signalling over UDP transport only.

UDP was selected as the initial implementation due to its simplicity and widespread use in SIP-based systems.

Support for TCP (for improved connection stability and NAT traversal) and TLS (for secure SIP signalling) is not yet implemented and will be considered in future enhancements.


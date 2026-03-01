#!/usr/bin/env python3
"""
Kingst LA Series — MCP Server
Exposes logic analyzer capture and protocol decode capabilities as MCP tools.

Run on the Linux machine where the analyzer is connected:
    python3 mcp_server.py

Connect from Windsurf / Claude Desktop via SSH tunnel:
    ssh -L 8765:localhost:8765 user@linux-host
Or via stdio (recommended for MCP):
    ssh user@linux-host python3 /path/to/mcp_server.py
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Minimal MCP server implementation (stdio transport, no external deps)
# ---------------------------------------------------------------------------

def _make_response(id_: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}

def _make_error(id_: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}

def _tool_result(content: str, is_error: bool = False) -> dict:
    return {
        "content": [{"type": "text", "text": content}],
        "isError": is_error,
    }


TOOLS = [
    {
        "name": "scan_device",
        "description": (
            "Scan for connected Kingst logic analyzer devices. "
            "Returns device name, channel count, and connection info."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "capture",
        "description": (
            "Capture logic signals from the connected Kingst analyzer. "
            "Returns the capture as a base64-encoded .sr (sigrok) file "
            "plus a summary of what was captured."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "channels": {
                    "type": "string",
                    "description": "Comma-separated channel list, e.g. 'CH0,CH1,CH2'. Default: CH0,CH1",
                },
                "samplerate": {
                    "type": "string",
                    "description": "Sample rate, e.g. '1m' (1MHz), '10m' (10MHz), '500k'. Default: 1m",
                },
                "duration": {
                    "type": "string",
                    "description": "Capture duration, e.g. '5s', '500ms', '10s'. Default: 5s",
                },
            },
            "required": [],
        },
    },
    {
        "name": "decode_uart",
        "description": (
            "Decode UART data from a capture. Can either use a previously saved "
            "capture file or trigger a new capture. Returns decoded ASCII text."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {
                    "type": "string",
                    "description": "Channel connected to UART TX/RX, e.g. 'CH0' or 'CH1'. Default: CH0",
                },
                "baudrate": {
                    "type": "integer",
                    "description": "UART baud rate. Common: 115200, 57600, 38400, 9600. Default: 115200",
                },
                "samplerate": {
                    "type": "string",
                    "description": "Sample rate for new capture. Should be at least 8x baudrate. Default: 1m",
                },
                "duration": {
                    "type": "string",
                    "description": "Capture duration. Default: 10s",
                },
                "capture_file": {
                    "type": "string",
                    "description": "Path to existing .sr capture file. If omitted, a new capture is taken.",
                },
            },
            "required": [],
        },
    },
    {
        "name": "decode_protocol",
        "description": (
            "Decode a protocol from a capture using any sigrok protocol decoder. "
            "Triggers a new capture and runs the specified decoder. "
            "Use list_decoders to see available decoders."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "decoder": {
                    "type": "string",
                    "description": "Sigrok decoder name, e.g. 'uart', 'spi', 'i2c', 'jtag', 'onewire'",
                },
                "decoder_options": {
                    "type": "string",
                    "description": (
                        "Decoder channel/option mapping, e.g. 'rx=CH0:baudrate=115200' "
                        "or 'clk=CH0:data=CH1'. See sigrok decoder docs."
                    ),
                },
                "channels": {
                    "type": "string",
                    "description": "Channels to capture, e.g. 'CH0,CH1'. Default: CH0,CH1",
                },
                "samplerate": {
                    "type": "string",
                    "description": "Sample rate. Default: 1m",
                },
                "duration": {
                    "type": "string",
                    "description": "Capture duration. Default: 5s",
                },
                "capture_file": {
                    "type": "string",
                    "description": "Path to existing .sr file. If omitted, a new capture is taken.",
                },
                "annotation_class": {
                    "type": "string",
                    "description": "Annotation class to show, e.g. 'rx-data', 'data'. Default: all",
                },
            },
            "required": ["decoder", "decoder_options"],
        },
    },
    {
        "name": "list_decoders",
        "description": "List all available sigrok protocol decoders.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Optional substring to filter decoder names, e.g. 'uart' or 'spi'",
                },
            },
            "required": [],
        },
    },
    {
        "name": "save_capture",
        "description": (
            "Take a new capture and save it to a named file for later use with "
            "decode_protocol or decode_uart."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Output filename, e.g. '/tmp/boot_capture.sr'",
                },
                "channels": {
                    "type": "string",
                    "description": "Channels to capture. Default: CH0,CH1",
                },
                "samplerate": {
                    "type": "string",
                    "description": "Sample rate. Default: 1m",
                },
                "duration": {
                    "type": "string",
                    "description": "Capture duration. Default: 10s",
                },
            },
            "required": ["filename"],
        },
    },
]


# ---------------------------------------------------------------------------
# sigrok helpers
# ---------------------------------------------------------------------------

DRIVER = "kingst-la2016"


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError as e:
        return -1, "", str(e)


def _sigrok_capture(channels: str, samplerate: str, duration: str, outfile: str) -> tuple[bool, str]:
    """Run a sigrok capture. Returns (success, message)."""
    cmd = [
        "sigrok-cli",
        "--driver", DRIVER,
        "--config", f"samplerate={samplerate}",
        "--channels", channels,
        "--time", duration,
        "-o", outfile,
    ]
    rc, stdout, stderr = _run(cmd, timeout=120)
    # sigrok-cli exits 0 on success; "Unexpected run state" on stderr is non-fatal
    if rc != 0:
        return False, f"sigrok-cli failed (rc={rc}): {stderr.strip()}"
    return True, stderr.strip()


def _sigrok_decode(capture_file: str, decoder_spec: str, annotation: str = "") -> tuple[bool, str]:
    """Run a sigrok decoder against a capture file. Returns (success, decoded_text)."""
    cmd = ["sigrok-cli", "-i", capture_file, "-P", decoder_spec]
    if annotation:
        cmd += ["-A", annotation]
    rc, stdout, stderr = _run(cmd, timeout=60)
    if rc != 0:
        return False, f"Decode failed (rc={rc}): {stderr.strip()}"
    return True, stdout


def _hex_bytes_to_text(raw_output: str) -> str:
    """Convert sigrok hex byte output (e.g. 'uart-1: 4D\nuart-1: 41') to ASCII."""
    lines = raw_output.strip().splitlines()
    byte_vals = []
    for line in lines:
        if ": " in line:
            hex_part = line.split(": ", 1)[1].strip()
            if len(hex_part) == 2:
                try:
                    byte_vals.append(int(hex_part, 16))
                except ValueError:
                    pass
    if not byte_vals:
        return raw_output  # return as-is if no hex bytes found
    return bytes(byte_vals).decode("latin-1")


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

def handle_scan_device(_args: dict) -> str:
    cmd = ["sigrok-cli", "--driver", DRIVER, "--scan"]
    rc, stdout, stderr = _run(cmd, timeout=30)
    combined = (stdout + stderr).strip()
    if rc != 0 and "not found" in combined:
        return "No Kingst device found. Check USB connection and that firmware was extracted."
    if "No devices found" in combined or (not combined):
        return "No devices found. Ensure the device is plugged in and firmware files are in ~/.local/share/sigrok-firmware/"
    # Strip the non-fatal "Unexpected run state" warning
    lines = [l for l in combined.splitlines() if "Unexpected run state" not in l]
    return "\n".join(lines).strip()


def handle_capture(args: dict) -> str:
    channels = args.get("channels", "CH0,CH1")
    samplerate = args.get("samplerate", "1m")
    duration = args.get("duration", "5s")

    with tempfile.NamedTemporaryFile(suffix=".sr", delete=False) as f:
        outfile = f.name

    try:
        ok, msg = _sigrok_capture(channels, samplerate, duration, outfile)
        if not ok:
            return f"Capture failed: {msg}"

        size = os.path.getsize(outfile)
        with open(outfile, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()

        # Get sample count from the file
        rc, info_out, _ = _run(["sigrok-cli", "-i", outfile, "--show"], timeout=10)
        sample_count = ""
        for line in info_out.splitlines():
            if "sample count" in line.lower():
                sample_count = line.strip()

        result = (
            f"Capture complete.\n"
            f"  Channels: {channels}\n"
            f"  Samplerate: {samplerate}\n"
            f"  Duration: {duration}\n"
            f"  File size: {size:,} bytes (compressed)\n"
        )
        if sample_count:
            result += f"  {sample_count}\n"
        result += f"\nCapture saved to: {outfile}\n"
        result += f"\nBase64-encoded .sr file (for download):\n{b64}"
        return result
    finally:
        pass  # keep tempfile for potential re-use by other tools


def handle_decode_uart(args: dict) -> str:
    channel = args.get("channel", "CH0")
    baudrate = args.get("baudrate", 115200)
    samplerate = args.get("samplerate", "1m")
    duration = args.get("duration", "10s")
    capture_file = args.get("capture_file", "")

    if not capture_file:
        with tempfile.NamedTemporaryFile(suffix=".sr", delete=False) as f:
            capture_file = f.name
        ok, msg = _sigrok_capture(channel, samplerate, duration, capture_file)
        if not ok:
            return f"Capture failed: {msg}"

    decoder_spec = f"uart:rx={channel}:baudrate={baudrate}"
    ok, raw = _sigrok_decode(capture_file, decoder_spec, f"uart=rx-data")
    if not ok:
        # Try without annotation filter
        ok, raw = _sigrok_decode(capture_file, decoder_spec)
    if not ok:
        return f"Decode failed: {raw}"
    if not raw.strip():
        return (
            f"No UART data decoded on {channel} at {baudrate} baud.\n"
            f"Try: different channel (CH0/CH1), different baudrate (57600, 38400, 9600), "
            f"or check physical connection."
        )

    text = _hex_bytes_to_text(raw)
    return f"UART decode ({channel} @ {baudrate} baud):\n\n{text}"


def handle_decode_protocol(args: dict) -> str:
    decoder = args.get("decoder", "")
    decoder_options = args.get("decoder_options", "")
    channels = args.get("channels", "CH0,CH1")
    samplerate = args.get("samplerate", "1m")
    duration = args.get("duration", "5s")
    capture_file = args.get("capture_file", "")
    annotation_class = args.get("annotation_class", "")

    if not decoder:
        return "Error: 'decoder' is required (e.g. 'uart', 'spi', 'i2c')"

    if not capture_file:
        with tempfile.NamedTemporaryFile(suffix=".sr", delete=False) as f:
            capture_file = f.name
        ok, msg = _sigrok_capture(channels, samplerate, duration, capture_file)
        if not ok:
            return f"Capture failed: {msg}"

    decoder_spec = f"{decoder}:{decoder_options}" if decoder_options else decoder
    annotation = f"{decoder}={annotation_class}" if annotation_class else ""

    ok, raw = _sigrok_decode(capture_file, decoder_spec, annotation)
    if not ok:
        return f"Decode failed: {raw}"
    if not raw.strip():
        return (
            f"No data decoded with '{decoder_spec}'.\n"
            f"Check channel assignments, signal levels, and decoder options."
        )

    # Try to convert hex bytes to text if output looks like hex
    if raw.count(": ") > 5 and all(
        len(p.strip()) == 2 for line in raw.splitlines()[:5]
        if ": " in line for p in [line.split(": ", 1)[1].strip()]
    ):
        text = _hex_bytes_to_text(raw)
    else:
        text = raw

    return f"Protocol decode ({decoder_spec}):\n\n{text}"


def handle_list_decoders(args: dict) -> str:
    filter_str = args.get("filter", "").lower()
    rc, stdout, stderr = _run(["sigrok-cli", "-L"], timeout=15)
    if rc != 0:
        return f"Failed to list decoders: {stderr}"
    lines = stdout.splitlines()
    # Find the decoders section
    in_decoders = False
    result = []
    for line in lines:
        if line.strip().startswith("Supported protocol decoders:"):
            in_decoders = True
            continue
        if in_decoders:
            if filter_str and filter_str not in line.lower():
                continue
            result.append(line)
    return "\n".join(result).strip() if result else "No decoders found."


def handle_save_capture(args: dict) -> str:
    filename = args.get("filename", "")
    channels = args.get("channels", "CH0,CH1")
    samplerate = args.get("samplerate", "1m")
    duration = args.get("duration", "10s")

    if not filename:
        return "Error: 'filename' is required"

    ok, msg = _sigrok_capture(channels, samplerate, duration, filename)
    if not ok:
        return f"Capture failed: {msg}"

    size = os.path.getsize(filename)
    return (
        f"Capture saved to: {filename}\n"
        f"  Channels: {channels}\n"
        f"  Samplerate: {samplerate}\n"
        f"  Duration: {duration}\n"
        f"  File size: {size:,} bytes"
    )


HANDLERS = {
    "scan_device": handle_scan_device,
    "capture": handle_capture,
    "decode_uart": handle_decode_uart,
    "decode_protocol": handle_decode_protocol,
    "list_decoders": handle_list_decoders,
    "save_capture": handle_save_capture,
}


# ---------------------------------------------------------------------------
# MCP stdio transport loop
# ---------------------------------------------------------------------------

def handle_request(req: dict) -> dict | None:
    method = req.get("method", "")
    id_ = req.get("id")
    params = req.get("params", {})

    if method == "initialize":
        return _make_response(id_, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "kingst-la-mcp", "version": "1.0.0"},
        })

    if method == "notifications/initialized":
        return None  # no response for notifications

    if method == "tools/list":
        return _make_response(id_, {"tools": TOOLS})

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        handler = HANDLERS.get(name)
        if not handler:
            return _make_response(id_, _tool_result(f"Unknown tool: {name}", is_error=True))
        try:
            result = handler(args)
            return _make_response(id_, _tool_result(result))
        except Exception as e:
            return _make_response(id_, _tool_result(f"Tool error: {e}", is_error=True))

    if method == "ping":
        return _make_response(id_, {})

    return _make_error(id_, -32601, f"Method not found: {method}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            sys.stdout.write(json.dumps(_make_error(None, -32700, f"Parse error: {e}")) + "\n")
            sys.stdout.flush()
            continue

        response = handle_request(req)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

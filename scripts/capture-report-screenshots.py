#!/usr/bin/env python3

import base64
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = "/home/mxscan/public_html/dev.mxscan.me"
OUTPUT = os.path.join(ROOT, "storage/app/report-screenshots")
CHROME = "/home/mxscan/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome"
LABEL = "".join(character for character in os.getenv("REPORT_SNAPSHOT_LABEL", "after") if character.isalnum() or character in "_-") or "after"
VALIDATE = os.getenv("REPORT_VALIDATE", "1") != "0"
PORT = 9333


class DevTools:
    def __init__(self, url):
        parsed = urllib.parse.urlparse(url)
        self.socket = socket.create_connection((parsed.hostname, parsed.port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode())
        response = self.socket.recv(4096)
        if b" 101 " not in response:
            raise RuntimeError(f"Chrome DevTools websocket upgrade failed: {response[:300]!r}")
        self.next_id = 1

    def send(self, method, params=None):
        message_id = self.next_id
        self.next_id += 1
        payload = json.dumps({"id": message_id, "method": method, "params": params or {}}).encode()
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes([0x81, 0x80 | length])
        elif length < 65536:
            header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", length)
        else:
            header = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", length)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(header + mask + masked)

        while True:
            message = self.receive()
            if message.get("id") == message_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    def receive(self):
        first = self._read_exact(2)
        opcode = first[0] & 0x0F
        length = first[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        if first[1] & 0x80:
            mask = self._read_exact(4)
        else:
            mask = None
        payload = self._read_exact(length)
        if mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        if opcode == 0x9:
            return self.receive()
        return json.loads(payload.decode())

    def _read_exact(self, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = self.socket.recv(remaining)
            if not chunk:
                raise RuntimeError("Chrome DevTools websocket closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


def wait_for_json(url):
    for _ in range(100):
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                return json.load(response)
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("Chrome DevTools endpoint did not start")


def open_page():
    request = urllib.request.Request(f"http://127.0.0.1:{PORT}/json/new?about:blank", method="PUT")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def capture(devtools, width, height, save):
    devtools.send("Emulation.setDeviceMetricsOverride", {
        "width": width,
        "height": height,
        "deviceScaleFactor": 1,
        "mobile": width < 768,
        "screenWidth": width,
        "screenHeight": height,
    })
    devtools.send("Page.enable")
    url = "file://" + os.path.join(OUTPUT, f"mxscan-me-report-{LABEL}.html")
    devtools.send("Page.navigate", {"url": url})
    time.sleep(0.5)

    expression = """(() => {
      const cards = [...document.querySelectorAll('.report-summary-card')];
      const buttons = [...document.querySelectorAll('button:not([hidden]), .mx-btn:not([hidden])')]
        .filter(el => getComputedStyle(el).display !== 'none');
      const issue = document.querySelector('.report-issue-panel');
      const evidence = document.querySelector('.report-evidence-panel');
      const solution = document.querySelector('.report-solution-panel');
      return {
        viewport: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
        summaryColumns: new Set(cards.slice(0, 4).map(el => Math.round(el.getBoundingClientRect().left))).size,
        smallTargets: buttons.filter(el => {
          const rect = el.getBoundingClientRect();
          return rect.width > 0 && rect.height > 0 && (rect.width < 44 || rect.height < 44);
        }).map(el => (el.innerText || el.getAttribute('aria-label') || el.outerHTML.slice(0, 160)).trim()).slice(0, 10),
        panelsStacked: !issue || !evidence || !solution ||
          (evidence.getBoundingClientRect().top >= issue.getBoundingClientRect().bottom - 1 &&
           solution.getBoundingClientRect().top >= evidence.getBoundingClientRect().bottom - 1),
      };
    })()"""
    result = devtools.send("Runtime.evaluate", {"expression": expression, "returnByValue": True})
    metrics = result["result"]["value"]

    if VALIDATE and metrics["scrollWidth"] > metrics["viewport"]:
        raise RuntimeError(f"{width}px page overflow: {metrics}")
    if VALIDATE and width < 768 and metrics["smallTargets"]:
        raise RuntimeError(f"{width}px touch targets below 44px: {metrics['smallTargets']}")
    if VALIDATE and width == 320 and metrics["summaryColumns"] != 1:
        raise RuntimeError(f"320px summary cards must stack: {metrics}")
    if VALIDATE and width in (375, 390) and metrics["summaryColumns"] != 2:
        raise RuntimeError(f"{width}px summary cards must use two columns: {metrics}")
    if VALIDATE and width < 768 and not metrics["panelsStacked"]:
        raise RuntimeError(f"{width}px remediation panels are not stacked")

    if save:
        screenshot = devtools.send("Page.captureScreenshot", {"format": "png", "fromSurface": True})
        filename = os.path.join(OUTPUT, f"mxscan-me-report-{LABEL}-{width}.png")
        with open(filename, "wb") as output:
            output.write(base64.b64decode(screenshot["data"]))
        print(f"Captured {filename}")


def main():
    profile = tempfile.mkdtemp(prefix="mxscan-chrome-")
    process = subprocess.Popen([
        CHROME,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--remote-allow-origins=*",
        f"--remote-debugging-port={PORT}",
        f"--user-data-dir={profile}",
        "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for_json(f"http://127.0.0.1:{PORT}/json/version")
        page = open_page()
        devtools = DevTools(page["webSocketDebuggerUrl"])
        for width, height, save in [
            (320, 1200, True),
            (375, 1200, False),
            (390, 1200, True),
            (768, 1200, False),
            (1024, 1200, False),
            (1440, 1600, True),
        ]:
            capture(devtools, width, height, save)
    finally:
        process.terminate()
        process.wait(timeout=5)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Report screenshot validation failed: {error}", file=sys.stderr)
        sys.exit(1)

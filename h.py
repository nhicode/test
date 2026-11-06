#!/usr/bin/env python3
# deob_client.py
# Chạy: python3 deob_client.py "https://rscripts.net/api/telemetry/v2/client.lua?s=6adfeb78f733a6e82c1455c2"

import argparse
import base64
import binascii
import re
import subprocess
import sys
from pathlib import Path

import requests


def fetch(url: str) -> str:
    r = requests.get(url, timeout=30, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    r.raise_for_status()
    return r.text


def detect(src: str) -> list[str]:
    hits = []
    low = src.lower()
    if "moonsec" in low or "moonloader" in low or "moon_" in low:
        hits.append("MoonSec")
    if "luraph" in low or "lph!" in low or "lph~" in low or "lph" in low:
        hits.append("Luraph")
    if "ironbrew" in low or "iron_brew" in low:
        hits.append("IronBrew")
    if "psu" in low and "obfusc" in low:
        hits.append("PSU")
    if "loadstring" in low:
        hits.append("loadstring-wrapper")
    if re.search(r"while\s+true\s+do", src) and re.search(r"pcall\s*\(", src):
        hits.append("VM-loop")
    return hits


def decode_string_char(src: str) -> str:
    def repl(m):
        args = m.group(1)
        parts = [p.strip() for p in args.split(",")]
        out = []
        for p in parts:
            try:
                if p.lower().startswith("0x"):
                    n = int(p, 16)
                else:
                    n = int(p)
                if 0 <= n <= 255:
                    out.append(chr(n))
                else:
                    return m.group(0)
            except ValueError:
                return m.group(0)
        s = "".join(out)
        s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
        return f'"{s}"'

    return re.sub(r"string\.char\s*\(([^()]*)\)", repl, src)


def decode_escapes(src: str) -> str:
    src = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), src)
    src = re.sub(r"\\(\d{1,3})", lambda m: chr(int(m.group(1)) & 0xFF), src)
    src = re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: chr(int(m.group(1), 16)), src)
    return src


def decode_base64_blobs(src: str) -> str:
    def repl(m):
        quote = m.group(1)
        blob = m.group(2)
        if len(blob) < 40:
            return m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            txt = raw.decode("utf-8", errors="strict")
            if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in txt):
                txt = txt.replace("\\", "\\\\").replace(quote, "\\" + quote)
                txt = txt.replace("\n", "\\n").replace("\r", "\\r")
                return f'{quote}{txt}{quote}'
        except Exception:
            pass
        return m.group(0)

    return re.sub(r"(['\"])([A-Za-z0-9+/=]{40,})\1", repl, src)


def extract_strings(src: str, out: Path):
    vals = []
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', src):
        s = m.group(1) if m.group(1) is not None else m.group(2)
        if s and len(s) >= 4:
            vals.append(s)
    out.write_text("\n".join(dict.fromkeys(vals)), encoding="utf-8")


def beautify(src: str, out: Path):
    out.write_text(src, encoding="utf-8")
    try:
        subprocess.run(["lua-format", "-i", str(out)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("-o", "--outdir", default="deob_out")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("[*] tải link...")
    raw = fetch(args.url)
    (outdir / "raw.lua").write_text(raw, encoding="utf-8")
    print(f"[*] raw: {len(raw)} bytes")

    hits = detect(raw)
    print("[*] dấu hiệu:", ", ".join(hits) if hits else "không rõ")

    stage = raw
    stage = decode_string_char(stage)
    stage = decode_escapes(stage)
    stage = decode_base64_blobs(stage)

    (outdir / "stage1.lua").write_text(stage, encoding="utf-8")
    extract_strings(stage, outdir / "strings.txt")
    beautify(stage, outdir / "pretty.lua")

    report = outdir / "report.txt"
    report.write_text(
        f"URL: {args.url}\n"
        f"Raw bytes: {len(raw)}\n"
        f"Detected: {', '.join(hits) if hits else 'unknown'}\n"
        f"Stage1 bytes: {len(stage)}\n",
        encoding="utf-8"
    )

    print(f"[*] xong: {outdir}/raw.lua, stage1.lua, pretty.lua, strings.txt, report.txt")
    if "Luraph" in hits:
        print("[!] Luraph VM: cần deobfuscator chuyên dụng, xem:")
        print("    https://github.com/larpcorrupt/luraph-v15-v14.x-deobfuscator")
        print("    https://github.com/caomod2077/Deobfuscator-Luraph-V15")
    if "MoonSec" in hits:
        print("[!] MoonSec: dùng Lua Deobfuscator Pro hoặc MoonSec V3 deob.")
    print("[*] mở pretty.lua; nếu còn VM thì dán raw.lua vào đây tao bóc tiếp.")


if __name__ == "__main__":
    main()

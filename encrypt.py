#!/usr/bin/env python3
"""Shrink your MP3s, then encrypt them so they can sit in a public GitHub repo.

Setup (once):   pip install cryptography
                ffmpeg must be installed to shrink the songs
                (Mac: brew install ffmpeg   or   conda install -c conda-forge ffmpeg)

Run it from the project folder, next to index.html:

    python encrypt.py "path/to/the/folder/with/your/mp3s"

Options:
    --kbps 96       smaller and faster (default 128)
    --no-shrink     keep the songs exactly as they are

It asks you to choose a code, then writes the scrambled songs into an
"audio" folder. Upload what is inside that folder (NOT your original mp3 files).
"""
import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from urllib.parse import unquote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 300_000

# Same order as the TRACKS list in index.html
FILES = [unquote(f) for f in [
    "KAYTRANADA,H.E.R. - Intimidated.mp3",
    "Tyler, The Creator,Ryan Beatty,Santigold - Lights On.mp3",
    "RAYE - Worth It.mp3",
    "Frank Ocean - Pink + White.mp3",
    "hard life,Arlo Parks - Sangria.mp3",
    "The Beatles - In My Life.mp3",
    "Fergie - Pedestal.mp3",
    "Tinashe - Pillow Fight.mp3",
    "FKA twigs - Piece Of Mine.mp3",
    "Kanye West - Family Business.mp3",
    "%D0%90%D0%9B%D0%9B%D0%81%D0%9A%D0%90,%D0%98%D0%BB%D1%8C%D1%8F%20-%20%D0%9D%D0%BE%D1%87%D0%B8%20%D0%BD%D0%B0%D0%BF%D1%80%D0%BE%D0%BB%D1%91%D1%82.mp3",
    "Magdalena Bay - Vampire in the Corner.mp3",
    "ROSAL%C3%8DA,The%20Weeknd%20-%20LA%20FAMA.mp3",
    "Priya Ragu - Lockdown.mp3",
    "Chris Lake,Amber Mark - In My Head.mp3",
]]


def nfc(name):
    return unicodedata.normalize("NFC", name)


def shrink(path, kbps):
    """Re-save one song as a smaller MP3 and return its bytes."""
    tmp = Path(tempfile.mkdtemp()) / "song.mp3"
    subprocess.run(
        ["ffmpeg", "-v", "error", "-y", "-i", str(path), "-vn", "-map_metadata", "-1",
         "-codec:a", "libmp3lame", "-b:a", f"{kbps}k", "-ar", "44100", str(tmp)],
        check=True)
    data = tmp.read_bytes()
    shutil.rmtree(tmp.parent, ignore_errors=True)
    return data


def encrypt_all(src, code, out, kbps=None):
    available = {nfc(p.name): p for p in Path(src).iterdir() if p.is_file()}
    missing = [n for n in FILES if nfc(n) not in available]
    if missing:
        raise FileNotFoundError("Can't find: " + "; ".join(missing))

    salt = os.urandom(16)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=ITERATIONS).derive(code.encode("utf-8"))
    aes = AESGCM(key)

    def seal(data):
        iv = os.urandom(12)
        return iv + aes.encrypt(iv, data, None)

    out = Path(out)
    out.mkdir(exist_ok=True)
    before = after = 0
    for i, name in enumerate(FILES, 1):
        path = available[nfc(name)]
        data = shrink(path, kbps) if kbps else path.read_bytes()
        sealed = seal(data)
        (out / f"t{i:02d}.enc").write_bytes(sealed)
        before += path.stat().st_size
        after += len(sealed)
        print(f"  {i:02d}/{len(FILES)}  {name}  ({path.stat().st_size/1e6:.1f} MB -> {len(sealed)/1e6:.1f} MB)")
    print(f"\nTotal: {before/1e6:.0f} MB -> {after/1e6:.0f} MB")

    cfg = {"salt": salt.hex(), "iter": ITERATIONS, "check": seal(b"awesome mix").hex()}
    (out / "config.json").write_text(json.dumps(cfg))


def main():
    ap = argparse.ArgumentParser(description="Shrink and encrypt the mixtape songs.")
    ap.add_argument("folder", help="folder that holds your 15 mp3 files")
    ap.add_argument("--kbps", type=int, default=128, help="quality of the shrunk songs (default 128, try 96 for even smaller)")
    ap.add_argument("--no-shrink", action="store_true", help="do not re-save the songs, keep them as they are")
    args = ap.parse_args()

    src = Path(args.folder).expanduser()
    if not src.is_dir():
        sys.exit(f"Not a folder: {src}")
    kbps = None if args.no_shrink else args.kbps
    if kbps and not shutil.which("ffmpeg"):
        sys.exit("ffmpeg is not installed, so the songs can't be shrunk.\n"
                 "Install it (Mac: brew install ffmpeg, or: conda install -c conda-forge ffmpeg)\n"
                 "or run again with --no-shrink.")

    code = getpass.getpass("Choose a code (a phrase works well): ").strip().lower()
    if len(code) < 8:
        sys.exit("Use at least 8 characters. Anyone can try guessing offline, so longer is safer.")
    if getpass.getpass("Type it again: ").strip().lower() != code:
        sys.exit("The two codes didn't match.")

    try:
        encrypt_all(src, code, Path(__file__).resolve().parent / "audio", kbps)
    except FileNotFoundError as e:
        sys.exit(str(e))
    print("\nDone. Upload the files inside the audio folder (t01.enc ... t15.enc and config.json).")
    print("The code is not saved anywhere. Keep it somewhere safe.")


if __name__ == "__main__":
    main()

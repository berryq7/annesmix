#!/usr/bin/env python3
"""Encrypt your MP3s so they can sit in a public GitHub repo.

Setup (once):   pip install cryptography
Run it from the project folder, next to index.html:

    python encrypt.py "path/to/the/folder/with/your/mp3s"

It asks you to choose a code, then writes the scrambled songs into an
"audio" folder. Upload that folder (NOT your original mp3 files).
"""
import getpass
import json
import os
import sys
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


def encrypt_all(src, code, out):
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
    for i, name in enumerate(FILES, 1):
        (out / f"t{i:02d}.enc").write_bytes(seal(available[nfc(name)].read_bytes()))
        print(f"  {i:02d}/{len(FILES)}  {name}")

    cfg = {"salt": salt.hex(), "iter": ITERATIONS, "check": seal(b"awesome mix").hex()}
    (out / "config.json").write_text(json.dumps(cfg))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    src = Path(sys.argv[1]).expanduser()
    if not src.is_dir():
        sys.exit(f"Not a folder: {src}")

    code = getpass.getpass("Choose a code (a phrase works well): ").strip().lower()
    if len(code) < 8:
        sys.exit("Use at least 8 characters. Anyone can try guessing offline, so longer is safer.")
    if getpass.getpass("Type it again: ").strip().lower() != code:
        sys.exit("The two codes didn't match.")

    try:
        encrypt_all(src, code, Path(__file__).resolve().parent / "audio")
    except FileNotFoundError as e:
        sys.exit(str(e))
    print("\nDone. Upload index.html, the jpg files and the audio folder.")
    print("The code is not saved anywhere. Keep it somewhere safe.")


if __name__ == "__main__":
    main()

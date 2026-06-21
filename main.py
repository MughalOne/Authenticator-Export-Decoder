import sys
import os
import base64
import subprocess
import shutil
import urllib.parse
from typing import Tuple, List, Dict

def b64_padding(s: str) -> str:
    s = s.strip()
    s = s.replace('-', '+').replace('_', '/')
    pad = (-len(s)) % 4
    if pad:
        s += '=' * pad
    return s

def decode_base64_payload(s: str) -> bytes:
    s = b64_padding(s)
    try:
        return base64.b64decode(s)
    except Exception as e:
        raise ValueError("Invalid base64 payload") from e

def parse_varint(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("Truncated varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift >= 64:
            raise ValueError("Varint too long")
    return result, pos

def skip_field(data: bytes, pos: int, wire_type: int) -> int:
    if wire_type == 0:  # varint
        _, pos = parse_varint(data, pos)
        return pos
    elif wire_type == 1:  # 64-bit
        return pos + 8
    elif wire_type == 2:  # length-delimited
        length, pos = parse_varint(data, pos)
        return pos + length
    elif wire_type == 5:  # 32-bit
        return pos + 4
    else:
        raise ValueError(f"Unsupported wire type: {wire_type} at pos {pos}")

def parse_otp_parameters(msg: bytes) -> Dict:
    pos = 0
    entry = {}
    while pos < len(msg):
        tag, pos = parse_varint(msg, pos)
        field_number = tag >> 3
        wire_type = tag & 0x7

        if field_number == 1 and wire_type == 2:  # secret bytes
            length, pos = parse_varint(msg, pos)
            entry['secret'] = msg[pos:pos+length]
            pos += length
        elif field_number == 2 and wire_type == 2:  # name string
            length, pos = parse_varint(msg, pos)
            entry['name'] = msg[pos:pos+length].decode('utf-8', errors='replace')
            pos += length
        elif field_number == 3 and wire_type == 2:  # issuer string
            length, pos = parse_varint(msg, pos)
            entry['issuer'] = msg[pos:pos+length].decode('utf-8', errors='replace')
            pos += length
        elif field_number == 4 and wire_type == 0:  # algorithm enum
            val, pos = parse_varint(msg, pos)
            entry['algorithm'] = val
        elif field_number == 5 and wire_type == 0:  # digits enum
            val, pos = parse_varint(msg, pos)
            entry['digits'] = val
        elif field_number == 6 and wire_type == 0:  # type enum
            val, pos = parse_varint(msg, pos)
            entry['type'] = val
        elif field_number == 7 and wire_type == 0:  # counter
            val, pos = parse_varint(msg, pos)
            entry['counter'] = val
        else:
            pos = skip_field(msg, pos, wire_type)
    return entry

def parse_migration_payload(data: bytes) -> List[Dict]:
    pos = 0
    entries = []
    while pos < len(data):
        tag, pos = parse_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x7

        if field_number == 1 and wire_type == 2:  # repeated OtpParameters
            length, pos = parse_varint(data, pos)
            sub = data[pos:pos+length]
            pos += length
            entries.append(parse_otp_parameters(sub))
        else:
            pos = skip_field(data, pos, wire_type)
    return entries

def build_otpauth_uri(entry: Dict) -> str:
    secret_bytes = entry.get('secret', b'')
    import base64 as _b64, urllib.parse as _up
    secret_b32 = _b64.b32encode(secret_bytes).decode('utf-8').rstrip('=')

    algo_map = {1: 'SHA1', 2: 'SHA256', 3: 'SHA512'}
    algorithm = algo_map.get(entry.get('algorithm', 1), 'SHA1')

    digits_map = {1: 6, 2: 8}
    digits = digits_map.get(entry.get('digits', 1), 6)

    type_map = {1: 'hotp', 2: 'totp'}
    otp_type = type_map.get(entry.get('type', 2), 'totp')

    name = entry.get('name', '')
    issuer = entry.get('issuer', '')

    if issuer:
        label = f"{issuer}:{name}"
    else:
        label = name

    label_enc = _up.quote(label, safe='')
    issuer_enc = _up.quote(issuer, safe='')

    uri = f"otpauth://{otp_type}/{label_enc}?secret={secret_b32}&issuer={issuer_enc}&algorithm={algorithm}&digits={digits}"
    if otp_type == 'totp':
        uri += "&period=30"
    else:
        if 'counter' in entry:
            uri += f"&counter={entry['counter']}"

    return uri

def extract_data_from_string(s: str) -> str:
    s = s.strip()
    if s.startswith('otpauth-migration://'):
        parsed = urllib.parse.urlparse(s)
        qs = urllib.parse.parse_qs(parsed.query)
        data_vals = qs.get('data') or qs.get('data=') or []
        if data_vals:
            return data_vals[0]
        idx = s.find('data=')
        if idx != -1:
            return s[idx+5:]
        raise ValueError("Couldn't find data= parameter in otpauth-migration URL")
    if s.startswith('data='):
        return s.split('data=',1)[1]
    return s

def scan_image_with_zbar(path: str) -> str:
    if not shutil.which('zbarimg'):
        raise EnvironmentError("zbarimg not found. Install zbar-tools (sudo apt install zbar-tools)")
    proc = subprocess.run(['zbarimg', '--raw', path], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"zbarimg failed: {proc.stderr.strip()}")
    return proc.stdout.strip()

def decode_input(input_arg: str) -> List[str]:
    if os.path.exists(input_arg):
        s = scan_image_with_zbar(input_arg)
    else:
        s = input_arg

    b64 = extract_data_from_string(s)
    raw = decode_base64_payload(b64)
    entries = parse_migration_payload(raw)
    uris = [build_otpauth_uri(e) for e in entries]
    return uris

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <image.png | otpauth-migration-url | base64-payload>")
        sys.exit(1)
    arg = sys.argv[1]
    try:
        uris = decode_input(arg)
    except Exception as e:
        print("Error decoding input:", e)
        sys.exit(2)

    for u in uris:
        print(u)

if __name__ == '__main__':
    main()

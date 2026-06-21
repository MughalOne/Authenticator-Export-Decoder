# Authenticator-Export-Decoder

Decode exported QR payloads from authenticator applications and recover TOTP/HOTP secrets, issuer names, account names, algorithms, digits, and other OTP metadata.

## About

**Authenticator-Export-Decoder** is a Python utility that helps you extract and decode OTP (One-Time Password) credentials from exported QR codes. This tool is useful for:

- Migrating authentication credentials between devices
- Backing up TOTP/HOTP secrets
- Recovering lost authentication metadata
- Analyzing authentication configurations

The tool supports multiple authenticator applications and extracts:
- 🔐 TOTP/HOTP secrets
- 📱 Issuer names and account identifiers
- ⚙️ Algorithm information
- 🔢 Digit configurations

## How to Use

### Installation

```bash
git clone https://github.com/MughalOne/Authenticator-Export-Decoder.git
cd Authenticator-Export-Decoder
pip install -r requirements.txt
```

### Usage

```bash
python3 gauth_decode.py <image.png>
python3 gauth_decode.py "otpauth-migration://offline?data=BASE64..."
python3 gauth_decode.py BASE64_PAYLOAD
```

### Requirements (for image scanning)

```bash
sudo apt install zbar-tools  # for zbarimg
```

## Credits

Made with ❤️ in **Pakistan**

---

For issues and contributions, visit the [GitHub repository](https://github.com/MughalOne/Authenticator-Export-Decoder).

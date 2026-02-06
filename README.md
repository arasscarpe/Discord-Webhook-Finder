
# WEBHOOK FINDER

A lightweight security-oriented scanner that detects **Discord webhooks** and **localhost references** inside files such as executables, scripts, archives, and text files.

This tool is designed for **analysis and auditing purposes**, helping users identify unintended or hidden webhook endpoints embedded in files.

---

## Features

* Detects **Discord webhook URLs**
* Detects **localhost / 127.0.0.1 / ::1 references**
* Scans the following file types:

  * `.exe`, `.dll` (PE sections & overlay)
  * `.py`, `.js`
  * `.txt`, `.json`, `.xml`
  * `.zip` (recursive: zip inside zip)
* Supports:

  * Plain text webhooks
  * Escaped webhooks
  * Base64-encoded webhooks
* File picker interface
* Automatic **administrator elevation**
* Menu-based interface (no sudden exits)
* Filters out unrelated URLs (Google, Twitter, docs, etc.)

---

## How It Works

The scanner performs a **raw byte-level analysis** of the selected file:

1. Reads the file as binary data
2. Normalizes escaped characters
3. Searches using flexible Discord webhook patterns
4. Attempts Base64 decoding where applicable
5. Recursively scans archives and embedded binaries
6. Reports only relevant findings based on strict rules

Only **actionable endpoints** are reported.

---

## Usage

1. Run the script (or compiled executable)
2. The application will automatically request administrator privileges
3. Choose **Start Scan** from the menu
4. Select a file using the file picker
5. Review detected webhooks or localhost references
6. Return to the main menu or exit

---

## Example Output

```
[1] DISCORD WEBHOOK
    Source: example.exe [OVERLAY]
    Value : https://discord.com/api/webhooks/...

[2] LOCALHOST
    Source: config.json
    Value : localhost reference
```

---

## Requirements

* Windows
* Python 3.9+
* Optional (for deeper `.exe` analysis):

  * `pefile`

Install optional dependency:

```
pip install pefile
```

---

## Intended Use

This project is intended for:

* Security research
* Malware analysis
* File auditing
* Educational purposes

**Do not use this tool for unauthorized scanning or malicious activity.**

---

## Disclaimer

This software is provided **as-is**, without warranty of any kind.
The author is not responsible for misuse or damage caused by this tool.

---

## License

MIT License

---

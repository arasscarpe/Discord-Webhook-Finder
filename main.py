import os, re, sys, ctypes, zipfile, io, base64
from tkinter import Tk, filedialog

try:
    import pefile
except:
    pefile = None

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def relaunch_admin():
    p = " ".join([f'"{a}"' for a in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, p, None, 1)
    sys.exit()

if not is_admin():
    relaunch_admin()

WEBHOOK_RE = re.compile(rb"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,20}/[A-Za-z0-9._-]{30,120}", re.I)
LOCAL_RE = re.compile(rb"(localhost|127\.0\.0\.1|::1)", re.I)
B64_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print("""
██╗    ██╗███████╗██████╗ ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗
██║    ██║██╔════╝██╔══██╗██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝
██║ █╗ ██║█████╗  ██████╔╝███████║██║   ██║██║   ██║█████╔╝
██║███╗██║██╔══╝  ██╔══██╗██╔══██║██║   ██║██║   ██║██╔═██╗
╚███╔███╔╝███████╗██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║  ██╗
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
                WEBHOOK FINDER
""")

def scan_bytes(data, src, out):
    for m in WEBHOOK_RE.findall(data):
        out.add(("DISCORD WEBHOOK", m.decode(errors="ignore"), src))
    if LOCAL_RE.search(data):
        out.add(("LOCALHOST", "localhost reference", src))
    for b in B64_RE.findall(data):
        try:
            d = base64.b64decode(b)
            for m in WEBHOOK_RE.findall(d):
                out.add(("DISCORD WEBHOOK (BASE64)", m.decode(errors="ignore"), src))
        except:
            pass

def scan_zip(data, src, out):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                try:
                    c = z.read(n)
                    scan_bytes(c, src + " -> " + n, out)
                    if c.startswith(b"PK\x03\x04"):
                        scan_zip(c, src + " -> " + n, out)
                except:
                    pass
    except:
        pass

def scan_pe(data, src, out):
    if not pefile:
        return
    try:
        pe = pefile.PE(data=data, fast_load=True)
        for s in pe.sections:
            scan_bytes(s.get_data(), src + " [PE]", out)
        ov = pe.get_overlay()
        if ov:
            scan_bytes(ov, src + " [OVERLAY]", out)
    except:
        pass

def scan_file(path):
    out = set()
    try:
        with open(path, "rb") as f:
            data = f.read()
    except:
        return out
    scan_bytes(data, path, out)
    if data.startswith(b"PK\x03\x04"):
        scan_zip(data, path, out)
    if data[:2] == b"MZ":
        scan_pe(data, path, out)
    return out

def pick_file():
    r = Tk()
    r.withdraw()
    p = filedialog.askopenfilename(
        title="Select file to scan",
        filetypes=[
            ("All files", "*.*"),
            ("Executables", "*.exe *.dll"),
            ("Archives", "*.zip"),
            ("Scripts", "*.py *.js"),
            ("Text", "*.txt *.json *.xml")
        ]
    )
    r.destroy()
    return p

def start_scan():
    banner()
    print("Select a file to scan.\n")
    path = pick_file()
    if not path:
        print("No file selected.")
        input("Press Enter to return to menu...")
        return
    print("Scanning...\n")
    res = scan_file(path)
    banner()
    if res:
        for i, (t, v, s) in enumerate(sorted(res), 1):
            print(f"[{i}] {t}")
            print(f"    Source: {s}")
            print(f"    Value : {v}\n")
    else:
        print("No Discord webhook or localhost reference found.")
    input("Press Enter to return to menu...")

def main():
    while True:
        banner()
        print("[1] Start Scan")
        print("[2] Exit\n")
        c = input("Select: ").strip()
        if c == "1":
            start_scan()
        elif c == "2":
            sys.exit()

if __name__ == "__main__":
    main()
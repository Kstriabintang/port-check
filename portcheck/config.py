"""Central configuration: file names, timeouts, thresholds, colors.

Edit values here to tune the scanner. Nothing in this module does I/O.
"""
import sys

# ---- Input files (matched case-insensitively, see parsing.find_file) ----
PROXY_FILE = "Proxy.txt"
PROVIDER_FILE = "provider.txt"

# ---- Output locations (TXT + JSON only, no CSV) ----
RESULTS_DIR = "results"
READY_DIR = "results/ready"                 # ready-to-use proxy lists
PROGRESS_FILE = "results/.progress.txt"     # live backup while scanning
ALL_PROXIES_FILE = "results/all_proxies.txt"
SMTP_PROXIES_FILE = "results/smtp_proxies.txt"
COUNTRY_REPORT_FILE = "results/country_report.txt"
SUBNET_REPORT_FILE = "results/subnet_report.txt"
HEALTHY_JSON_FILE = "results/healthy_proxies.json"

# ---- Concurrency & timeouts (seconds) ----
WORKERS = 100              # parallel checks
TIMEOUT_PORT = 3           # quick port-open check
TIMEOUT = 5                # type detection
TIMEOUT_EXIT = 10          # open ip-api through the proxy
TIMEOUT_BANNER = 1.5       # passive banner wait
TIMEOUT_SMTP_PROXY = 12    # one SMTP test through a proxy

# ---- GeoIP lookup (ip-api.com) ----
INFO_HOST = "ip-api.com"
INFO_PORT = 80
INFO_FIELDS = "status,message,country,city,isp,org,as,mobile,proxy,hosting,query"
INFO_PATH = f"/json?fields={INFO_FIELDS}"

# ---- SMTP capability test ----
# The scanner tries to relay to this domain's MX (port 25, stops before DATA),
# then falls back to submission ports on common relays. No email is ever sent.
TARGET_EMAIL = "hello@ksatriabintangsamudra.com"
FROM_EMAIL = "probe@ksatriabintangsamudra.com"
SUBMISSION_TARGETS = [
    ("smtp.gmail.com", 587),
    ("smtp-mail.outlook.com", 587),
    ("smtp.gmail.com", 465),
]

# ---- Speed grading (milliseconds) ----
FAST_MAX = 1000            # <= this -> FAST
MEDIUM_MAX = 3000          # <= this -> MEDIUM, above -> SLOW
SLOW_MAX = 6000            # > this  -> BAD (dropped from ready lists)

# ---- Subnet flooding control ----
# Real flooding = few IPs exposed on many ports. The strongest signal is the
# ports-per-IP ratio; a low usable ratio is a secondary signal.
FLOOD_MIN_ENTRIES = 6          # a /24 must have at least this many entries to be judged
FLOOD_PORTS_PER_IP = 4         # entries/unique_ips >= this -> flooding
FLOOD_USABLE_RATIO = 0.30      # secondary: usable/entries below this -> flooding
# Cap how many healthy proxies from a single /24 may enter the ready lists,
# so one block cannot dominate. 0 = no cap.
READY_PER_SUBNET_CAP = 8

# ---- Catch-all / honeypot skip ----
# Some hosts accept connections on EVERY port but are never a working proxy
# (catch-all / honeypot). Once an IP has this many "open but not a proxy" hits,
# skip its remaining ports — this also massively speeds up the scan.
CATCHALL_SKIP_AFTER = 3

# ---- Work-queue mode ----
# When reading from Proxy.txt, remove each checked proxy from the file so a
# stopped run can resume from what's left. The file is rewritten every
# QUEUE_FLUSH_EVERY completed proxies (and once at the end / on stop).
QUEUE_FLUSH_EVERY = 500

# ---- Provider mode SMTP targets (greeting-only check) ----
PROVIDER_SMTP_TARGETS = [
    ("gmail-smtp-in.l.google.com", 25),
    ("smtp.gmail.com", 587),
    ("outlook-com.olc.protection.outlook.com", 25),
    ("smtp.office365.com", 587),
]
TIMEOUT_SMTP_GREETING = 10

# ---- Terminal colors (auto-disabled when output is not a TTY) ----
USE_COLOR = sys.stdout.isatty()
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
RED = "\033[91m" if USE_COLOR else ""
GRAY = "\033[90m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""

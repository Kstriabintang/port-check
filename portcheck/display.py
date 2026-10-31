"""Live terminal display: spinner, progress bar, per-proxy lines."""
import sys
import threading
import time

from . import config
from .geoip import isp_text

C = config


def _smtp_tag(r):
    parts = []
    if r["smtp_ok"]:
        parts.append(f"{C.GREEN}[SMTP OK {r['smtp_route']}]{C.RESET}")
    elif r["active"] and r["smtp_code"]:
        parts.append(f"{C.YELLOW}[SMTP {r['smtp_code']}]{C.RESET}")
    if r["active"] and r["speed"] != "-":
        color = C.GREEN if r["speed"] == "FAST" else (
            C.YELLOW if r["speed"] in ("MEDIUM", "SLOW") else C.RED)
        parts.append(f"{color}[{r['speed']} {r['ms']}ms]{C.RESET}")
    return (" " + " ".join(parts)) if parts else ""


def line_for(r):
    name = f"{r['host']}:{r['port']}"
    if r["active"]:
        d = r["info"]
        return (f"{C.GREEN}OK   {name:<24}{r['type']:<7}{r['service']:<16}"
                f"{str(r['ms']) + 'ms':>7}  {d.get('country', '-'):<14}{isp_text(d)}{C.RESET}"
                f"{_smtp_tag(r)}")
    if r["open"]:
        return (f"{C.YELLOW}OPEN {name:<24}{r['type']:<7}{r['service']}{C.RESET}"
                f"{_smtp_tag(r)}")
    return f"{C.RED}DOWN {name}{C.RESET}"


class Display:
    FRAMES = "|/-\\"

    def __init__(self, total):
        self.total = total
        self.done = self.active = self.open_only = self.down = 0
        self.skipped = 0
        self.lock = threading.Lock()
        self.start = time.time()
        self.frame = 0
        self.running = False

    def _bar(self):
        width = 26
        filled = int(width * self.done / self.total) if self.total else width
        secs = time.time() - self.start
        eta = ""
        if self.done and self.done < self.total:
            eta = f" eta ~{int(secs / self.done * (self.total - self.done))}s"
        spin = self.FRAMES[self.frame % len(self.FRAMES)]
        skip = f" {C.GRAY}skip {self.skipped}{C.RESET}" if self.skipped else ""
        return (f"{C.CYAN}{spin} [{'#' * filled}{'.' * (width - filled)}] "
                f"{self.done}/{self.total}{C.RESET}  "
                f"{C.GREEN}ok {self.active}{C.RESET} {C.YELLOW}open {self.open_only}{C.RESET} "
                f"{C.RED}down {self.down}{C.RESET}{skip}  {C.GRAY}{int(secs)}s{eta}{C.RESET}")

    def _draw(self):
        if C.USE_COLOR:
            sys.stdout.write("\r\033[2K" + self._bar())
            sys.stdout.flush()

    def _animate(self):
        while self.running:
            with self.lock:
                self.frame += 1
                self._draw()
            time.sleep(0.1)

    def start_animation(self):
        self.running = True
        threading.Thread(target=self._animate, daemon=True).start()

    def note(self, text):
        with self.lock:
            if C.USE_COLOR:
                sys.stdout.write("\r\033[2K")
            sys.stdout.write(text + "\n")
            self._draw()
            sys.stdout.flush()

    def record(self, r):
        with self.lock:
            self.done += 1
            if r.get("skipped"):
                self.skipped = getattr(self, "skipped", 0) + 1
            elif r["active"]:
                self.active += 1
            elif r["open"]:
                self.open_only += 1
            else:
                self.down += 1
            # Show only the useful extremes: OK (green) and DOWN (red).
            # OPEN and skipped proxies are counted but hidden to keep the feed clean.
            if r["active"] or (not r["open"] and not r.get("skipped")):
                if C.USE_COLOR:
                    sys.stdout.write("\r\033[2K")
                sys.stdout.write(line_for(r) + "\n")
            self._draw()
            sys.stdout.flush()

    def finish(self):
        self.running = False
        time.sleep(0.15)
        with self.lock:
            if C.USE_COLOR:
                sys.stdout.write("\r\033[2K")
            sys.stdout.flush()

"""Entry point logic: parse args, run checks in parallel, write results."""
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config, report, provider_mode
from .parsing import read_proxies, raise_file_limit, find_file
from .checker import check_proxy, reset_catchall_tracker, catchall_skipped_count
from .display import Display
from .geoip import batch_lookup
from .queue import ProxyQueue

C = config


def _enrich_open_proxies(results, display):
    """For proxies whose port is open but unusable, look up ISP via direct batch call."""
    needed, ip_by_host = [], {}
    for r in results:
        if r["open"] and not r["info"]:
            try:
                ip_by_host[r["host"]] = socket.gethostbyname(r["host"])
                needed.append(ip_by_host[r["host"]])
            except OSError:
                pass
    if not needed:
        return
    display.note(f"{C.GRAY}Looking up ISP for {len(needed)} OPEN proxies ...{C.RESET}")
    found = batch_lookup(needed, log=display.note)
    for r in results:
        if r["open"] and not r["info"] and ip_by_host.get(r["host"]) in found:
            r["info"], r["info_source"] = found[ip_by_host[r["host"]]], "incoming"


def run_scan(argv_targets):
    try:
        proxies, skipped = read_proxies(argv_targets)
    except FileNotFoundError as e:
        sys.exit(str(e))
    if skipped:
        print(f"{C.GRAY}{skipped} lines skipped (bad format){C.RESET}")
    if not proxies:
        sys.exit("No proxies to check.")

    raise_file_limit()
    reset_catchall_tracker()
    # Work-queue mode: only when reading from the file (not CLI args).
    queue_path = None if argv_targets else find_file(config.PROXY_FILE)
    queue = ProxyQueue(queue_path)
    target_domain = config.TARGET_EMAIL.split("@")[-1]
    print(f"Checking {len(proxies)} proxies | {config.WORKERS} parallel | "
          f"port timeout {config.TIMEOUT_PORT}s | SMTP target {config.TARGET_EMAIL} | "
          f"Ctrl+C to stop\n")
    if queue.active:
        print(f"{C.GRAY}Queue mode: checked proxies are removed from "
              f"{config.PROXY_FILE} so a stopped run resumes from the rest.{C.RESET}\n")

    display = Display(len(proxies))
    progress = report.ProgressWriter()
    results = []
    ex = ThreadPoolExecutor(max_workers=config.WORKERS)
    futures = [ex.submit(check_proxy, item, target_domain) for item in proxies]
    display.start_animation()
    interrupted = False
    try:
        for f in as_completed(futures):
            r = f.result()
            results.append(r)
            display.record(r)
            progress.write(r)
            queue.mark_done(r["host"], r["port"])
            if queue.active and len(results) % config.QUEUE_FLUSH_EVERY == 0:
                queue.flush()
    except KeyboardInterrupt:
        interrupted = True
        for f in futures:
            f.cancel()
        display.note(f"{C.YELLOW}Stopped, writing partial results ...{C.RESET}")
    finally:
        display.finish()
        ex.shutdown(wait=False)
        # Persist the remaining queue no matter how we exit.
        try:
            queue.flush()
        except Exception:
            pass

    # Enrichment hits the network for every OPEN proxy; skip it when interrupted
    # (and it can take a while on big lists). Guard finalization so a second
    # Ctrl+C still writes the result files from whatever was collected.
    if not interrupted:
        try:
            _enrich_open_proxies(results, display)
        except KeyboardInterrupt:
            interrupted = True
    try:
        stats = report.write_all(results)
    except KeyboardInterrupt:
        stats = report.write_all(results)  # retry once; writing is fast
    progress.close(keep=interrupted)
    report.print_summary(results, len(proxies))
    if interrupted:
        print(f"{C.YELLOW}(partial run: {len(results)}/{len(proxies)} checked "
              f"before stop — result files reflect what was collected){C.RESET}")
    if queue.active:
        left = queue.pending_count()
        if left:
            print(f"{C.CYAN}{left} proxies left in {config.PROXY_FILE} — "
                  f"run again to continue.{C.RESET}")
        else:
            print(f"{C.GREEN}All proxies checked; {config.PROXY_FILE} is now empty.{C.RESET}")

    skipped = catchall_skipped_count()
    if skipped:
        print(f"{C.GRAY}Catch-all/honeypot IPs auto-skipped: {skipped} "
              f"(open on many ports, never a real proxy).{C.RESET}")

    if stats["floods"]:
        print(f"\n{C.YELLOW}Flooding subnets detected "
              f"({len(stats['floods'])}):{C.RESET} "
              f"{C.GRAY}many padded entries, few usable proxies{C.RESET}")
        for d in stats["floods"][:5]:
            print(f"  {C.YELLOW}{d['subnet']:<18}{C.RESET} "
                  f"{d['entries']} entries / {d['unique_ips']} IPs "
                  f"({d['ports_per_ip']} ports/IP) -> "
                  f"only {d['usable']} usable, {d['smtp']} SMTP")
        if len(stats["floods"]) > 5:
            print(f"  {C.GRAY}... and {len(stats['floods']) - 5} more "
                  f"(see {config.SUBNET_REPORT_FILE}){C.RESET}")
        print(f"  {C.GRAY}Tip: prune these ranges from Proxy.txt to clean the list.{C.RESET}")
    if stats["capped"]:
        print(f"{C.GRAY}{stats['capped']} healthy proxies held back from ready lists "
              f"(per-subnet cap = {config.READY_PER_SUBNET_CAP}).{C.RESET}")

    print(f"\n{C.BOLD}Result files (see README.md for column meanings):{C.RESET}")
    print(f"  {config.ALL_PROXIES_FILE}      all proxies")
    if stats["smtp"]:
        print(f"  {C.GREEN}{config.SMTP_PROXIES_FILE}     {stats['smtp']} SMTP-capable, grouped by provider{C.RESET}")
    print(f"  {config.COUNTRY_REPORT_FILE}   per-country quality ({stats['countries']} countries)")
    print(f"  {config.SUBNET_REPORT_FILE}    per-/24 breakdown (flooding flagged)")
    print(f"  {config.HEALTHY_JSON_FILE} {stats['healthy']} healthy proxies (JSON)")
    print(f"  {config.READY_DIR}/              ready-to-use lists: fast / socks5 / http / smtp")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--provider" in argv:
        i = argv.index("--provider")
        value = argv[i + 1] if i + 1 < len(argv) else None
        return provider_mode.run(value)
    if "--recover" in argv:
        from . import recover
        i = argv.index("--recover")
        path = argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("-") else None
        return recover.run(path)
    # Any remaining args are treated as explicit proxy targets.
    return run_scan(argv or None)

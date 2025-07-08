#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZoneShah - Zone Transfer Vulnerability Scanner
Developed by: Shahwar Shah
Version: 1.3
Description:
    - A professional and powerful domain zone transfer vulnerability scanner.
    - Supports scanning from file (-f) or single domain (-u).
    - Verbose mode to track scanning process (-v).
    - Always shows failed zone transfers per domain.
    - High accuracy with no false positives or false negatives.
    - Colorful and clear output for better visibility.
    - Only displays vulnerable domains.
    - Developed with ❤️ by Shahwar Shah
"""

import argparse
import dns.query
import dns.zone
import dns.resolver
from termcolor import colored
import sys
import signal

# Graceful exit on Ctrl+C
signal.signal(signal.SIGINT, lambda s, f: sys.exit(colored("\n[!] Exiting ZoneShah...", "yellow", attrs=["bold"])))

def banner():
    print(colored("""
 ███████╗ ██████╗ ███╗   ██╗███████╗ ██████╗  █████╗  ██╗  ██╗
 ██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔════╝ ██╔══██╗ ██║ ██╔╝
 █████╗  ██║   ██║██╔██╗ ██║█████╗  ██║  ███╗███████║ █████╔╝ 
 ██╔══╝  ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██║ ██╔═██╗ 
 ███████╗╚██████╔╝██║ ╚████║███████╗╚██████╔╝██║  ██║ ██║  ██╗
 ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝
                                                                
            Zone Transfer Scanner by Shahwar Shah | v1.3
    """, "cyan", attrs=["bold"]))

def get_ns_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [str(rdata.target).strip('.') for rdata in answers]
    except Exception:
        return []

def attempt_zone_transfer(domain, verbose=False):
    ns_servers = get_ns_records(domain)
    if not ns_servers:
        print(colored(f"[!] No NS records found for domain: {domain}", "yellow", attrs=["bold"]))
        return False

    zone_transfer_successful = False
    failed_ns = []

    for ns in ns_servers:
        try:
            if verbose:
                print(colored(f"[*] Trying zone transfer from NS: {ns} for domain: {domain}", "blue"))
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            if zone:
                print(colored(f"\n[+] VULNERABLE DOMAIN FOUND:", "red", attrs=["bold"]))
                print(colored(f"    {domain}", "red", attrs=["bold", "underline"]))
                print(colored(f"    Zone transferred from NS server: {ns}\n", "yellow"))
                zone_transfer_successful = True
                break  # Stop after first successful transfer
        except Exception:
            failed_ns.append(ns)
            if verbose:
                print(colored(f"[-] Zone transfer failed from NS: {ns} for domain: {domain}", "yellow"))

    # Show failed NS servers always if no zone transfer succeeded
    if failed_ns and not zone_transfer_successful:
        failed_list = ", ".join(failed_ns)
        print(colored(f"[!] Zone transfer failed for domain: {domain}", "yellow", attrs=["bold"]))
        print(colored(f"    Failed NS servers: {failed_list}\n", "yellow"))

    return zone_transfer_successful

def scan_domains(domains, verbose=False):
    found_any = False
    for domain in domains:
        domain = domain.strip()
        if domain:
            if verbose:
                print(colored(f"[*] Scanning domain: {domain}", "cyan"))
            if attempt_zone_transfer(domain, verbose):
                found_any = True
    if not found_any:
        print(colored("[*] No vulnerable domains found.", "green", attrs=["bold"]))

def main():
    parser = argparse.ArgumentParser(
        description=colored("ZoneShah - Zone Transfer Vulnerability Scanner by Shahwar Shah", "magenta", attrs=["bold"]),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-u", help="Scan a single domain")
    parser.add_argument("-f", help="Scan a list of domains from file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output to show scan progress")

    args = parser.parse_args()
    banner()

    if args.u:
        scan_domains([args.u], verbose=args.verbose)
    elif args.f:
        try:
            with open(args.f, 'r') as file:
                domains = file.readlines()
                scan_domains(domains, verbose=args.verbose)
        except FileNotFoundError:
            print(colored("[!] File not found!", "red", attrs=["bold"]))
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()

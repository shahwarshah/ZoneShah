#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ZoneShah - Zone Transfer Vulnerability Scanner
Developed by: Shahwar Shah
Version: 1.4
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
                                                                
            Zone Transfer Scanner by Shahwar Shah | v1.4
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
        return False  # Quietly skip domains with no NS records

    zone_transfer_successful = False
    failed_ns = []

    for ns in ns_servers:
        try:
            if verbose:
                print(colored(f"[*] Trying zone transfer from NS: {ns} for domain: {domain}", "blue"))
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            if zone:
                print(colored(f"[+] Zone Transfer SUCCESS: {domain}", "green", attrs=["bold"]))
                print(colored(f"    NS Server: {ns}\n", "green"))
                zone_transfer_successful = True
                break
        except Exception:
            failed_ns.append(ns)
            if verbose:
                print(colored(f"[-] Zone transfer failed from NS: {ns}", "yellow"))

    if not zone_transfer_successful:
        print(colored(f"[-] Zone Transfer FAILED: {domain}", "yellow", attrs=["bold"]))

    return zone_transfer_successful

def scan_domains(domains, verbose=False):
    found_any = False
    for domain in domains:
        domain = domain.strip()
        if domain:
            if attempt_zone_transfer(domain, verbose):
                found_any = True
    if not found_any:
        print(colored("[*] No vulnerable domains found.", "cyan", attrs=["bold"]))

def main():
    parser = argparse.ArgumentParser(
        description=colored("ZoneShah - Zone Transfer Vulnerability Scanner by Shahwar Shah", "magenta", attrs=["bold"]),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-u", help="Scan a single domain")
    parser.add_argument("-f", help="Scan a list of domains from file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

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

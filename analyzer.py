#!/usr/bin/env python3
"""
analyzer.py
Simple SSH auth log analyzer that aggregates failed login attempts by IP and username,
exports a CSV report, and prints suspicious IPs above a threshold.
Usage:
    python3 analyzer.py sample_auth.log --threshold 5 --csv report.csv
"""

import argparse
import re
import csv
from collections import defaultdict

FAILED_REGEX = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)')

def analyze_log(path, threshold=5):
    ip_counts = defaultdict(int)
    user_counts = defaultdict(int)
    lines = 0
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            lines += 1
            m = FAILED_REGEX.search(line)
            if m:
                user = m.group(1)
                ip = m.group(2)
                ip_counts[ip] += 1
                user_counts[user] += 1

    suspicious_ips = [ip for ip, c in ip_counts.items() if c >= threshold]
    return {
        'lines': lines,
        'ip_counts': dict(ip_counts),
        'user_counts': dict(user_counts),
        'suspicious_ips': suspicious_ips
    }

def write_csv(report_path, ip_counts, user_counts):
    with open(report_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Type','Value','Count'])
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1]):
            writer.writerow(['IP', ip, cnt])
        for user, cnt in sorted(user_counts.items(), key=lambda x: -x[1]):
            writer.writerow(['User', user, cnt])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('logfile', help='Path to auth log (sample_auth.log)')
    parser.add_argument('--threshold', type=int, default=5, help='Threshold for suspicious IPs')
    parser.add_argument('--csv', default=None, help='Output CSV file (optional)')
    args = parser.parse_args()

    report = analyze_log(args.logfile, args.threshold)
    print(f"Lines analyzed: {report['lines']}")
    print("Top IPs by failed attempts:")
    for ip, c in sorted(report['ip_counts'].items(), key=lambda x: -x[1])[:10]:
        note = " [SUSPICIOUS]" if ip in report['suspicious_ips'] else ""
        print(f"  {ip}: {c}{note}")
    print("\nTop targeted usernames:")
    for user, c in sorted(report['user_counts'].items(), key=lambda x: -x[1])[:10]:
        print(f"  {user}: {c}")

    if args.csv:
        write_csv(args.csv, report['ip_counts'], report['user_counts'])
        print(f"\nCSV report written to {args.csv}")

if __name__ == '__main__':
    main()

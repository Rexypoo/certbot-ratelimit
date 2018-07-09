#!/usr/bin/env python

from __future__ import print_function

import re
from datetime import datetime as dt
from datetime import timedelta as td
import urllib2
import warnings
import os
import glob
import argparse
import contextlib
import sys

def get_public_suffixes():
    """Fetch the public suffix list from publicsuffix.org."""

    suffixes_url = "https://publicsuffix.org/list/public_suffix_list.dat"
    with contextlib.closing(urllib2.urlopen(suffixes_url)) as suffixes_req:
        suffixes_text = suffixes_req.read().decode("utf-8")
        suffixes_list = suffixes_text.split("\n")
        return [ s for s in suffixes_list if s and (s[:2] != "//")]

SUFFIXES=get_public_suffixes()

def natural_sorter(text_or_path):
    """Split digits from a string for natural sorting."""
    
    substrings = [ int(s) if s.isdigit() else s
                 for s in re.split("(\d+)",str(text_or_path))]
    return substrings

def find_recent_sessions(logs,hours=7*24):
    """Parse logs from letsencrypt to find recent requests."""

    oldest_ts = dt.now() - td(hours=hours)

    ts_re = re.compile("^....-..-.. ..:..:..,...:")
    ts_form = "%Y-%m-%d %H:%M:%S,%f"
    ts_len = 23

    session_flag = ":DEBUG:certbot.main:certbot version: "

    sessions=[]

    logging = False
    for log in logs[::-1]:
        mod_time = dt.fromtimestamp(os.stat(log).st_mtime)
        if mod_time > oldest_ts:
            with open(str(log),'r') as log_fp:
                for line in log_fp:
                    # Don't start log until the specified time
                    if not logging and ts_re.match(line):
                        ts = dt.strptime(line[:ts_len],ts_form)
                        if ts > oldest_ts:
                            logging = True
                    if logging:
                        if session_flag in line:
                            try:
                                sessions.append(session)
                            except NameError:
                                # If no session
                                pass
                            session=[]  # Reset the session
                        session.append(line[:-1])
    if logging:
        # Append the last session
        sessions.append(session)
    return sessions

def get_session_domains(session):
    """Extract the requested domains from a certbot session"""    

    arguments = session[1]
    if ("Arguments: []" in arguments) or ("'--dry-run'" in arguments) or ("'--staging'" in arguments):
        return

    session_sites = []
    for line in session:
        # Does this help or harm?
        if ":error:" in line.lower():
            return
        try:
            if line.split('"')[1] == "value":
                session_sites.append(line.split('"')[3])
        except IndexError:
            pass
    if session_sites:
        return tuple(sorted(set(session_sites)))

def get_requested_domains(sessions):
    """Get all requested domains from certbot sessions"""

    domains = []

    for session in sessions:
        session_domains = get_session_domains(session)
        if session_domains:
            domains.append(session_domains)

    return domains

def get_public_domain(domain,suffixes=SUFFIXES):
    """Take a subdomain and return the public domain"""

    suffixes.append("")
    suffixes.sort(key=lambda x: len(x),reverse=True)
    
    for suffix in suffixes:
        if len(suffix) < len(domain):
            if domain.endswith("."+suffix):
                break

    if suffix:
        num_parts = len(suffix.split(".")) + 1
        domain_leaf = domain.split(".")[-num_parts]
        public_domain = ".".join((domain_leaf,suffix))
    else:
        warn_txt="Could not identify the suffix of domain: {}"
        warnings.warn(warn_txt.format(domain),SyntaxWarning)
        public_domain = domain

    return public_domain

def count_registered_domains(sessions,suffixes=SUFFIXES):
    """Generate a dictionary for requests per registered domain"""

    domain_counts = {}

    for session_subdomains in get_requested_domains(sessions):
        registered_domains = [get_public_domain(d) for d in session_subdomains]

        for domain in set(registered_domains):
            if domain not in domain_counts:
                domain_counts[domain] = 0
            domain_counts[domain] += 1

    return domain_counts

def count_duplicate_certificates(sessions):
    """Generate a dictionary for duplicate certificate counts"""

    requested_domains_list = get_requested_domains(sessions)

    requested_domains_count = {}
    for requested_domains in requested_domains_list:
        domains = tuple(requested_domains)
        if domains not in requested_domains_count:
            requested_domains_count[domains] = 0
        requested_domains_count[domains] += 1
    
    return requested_domains_count

def count_failed_validations(sessions):
    """Count failed challenges from certbot logs"""

    failed_validations = 0
    
    for session in sessions:
        for line in session:
            if "'--staging'" in line:
                break
            if 'FailedChallenge' in line:
                failed_validations += 1

    return failed_validations

def summarize_dupe_certs(sessions,domains=(),limit="5/wk"):
    """Print a summary of duplicate certs (if any)"""

    domains = tuple(sorted(domains))
    
    dupe_cert_count = count_duplicate_certificates(sessions)
    
    header = "Summary of duplicate certificates (limit {}):"

    header = header.format(limit)

    duplicates = False

    if dupe_cert_count:
        if domains in dupe_cert_count:
            print(header)
            count = dupe_cert_count[domains]
            if count == 1:
                print("\t1 copy of")
            else:
                print("\t{} copies of".format(count))
            for domain in domains:
                print("\t\t{}".format(domain))
            duplicates = True
        elif not domains:
            headers_shown = False
            for domains,count in sorted(dupe_cert_count.items()):
                if count > 1:
                    if not headers_shown:
                        print(headers)
                        headers_shown=True
                    print("\t{} copies of".format(count))
                    for domain in domains:
                        print("\t\t{}".format(domain))
                    duplicates = True
    
    return duplicates

def summarize_registered_domains(sessions,domains=(),limit="20/wk"):
    """Print a summary of duplicate certs (if any)"""

    registrations = False

    domain_reg_count = count_registered_domains(sessions)

    header = "Summary of domain registrations (limit {}):"
    header = header.format(limit)

    domains = set([get_public_domain(d) for d in domains])

    if domains:
        print(header)
        for domain in domains:
            if domain in domain_reg_count:
                count = domain_reg_count[domain]
                print('\t{: <70}{: >3}'.format(domain+':',count))
            else:
                print('\t{: <70}{: >3}'.format(domain+':',0))
            registrations = True
    else:
        if domain_reg_count:
            print(header)
            for domain,count in domain_reg_count.items():
                print('\t{: <70}{: >3}'.format(domain+':',count))
            registrations = True

def summarize_failed_validations(sessions,limit="5/hr"):
    """Print a summary of failed validations"""

    failures = False

    header = "Summary of failed validations (limit {})"
    header = header.format(limit)
    
    failed_validations = count_failed_validations(sessions)
    if failed_validations > 0:
        print(header)
        print("\tFailed Validations:{: >54}".format(failed_validations))
        print("\t(REMINDER: use '--staging' when having validation problems)")
        failures = True

    return failures

def summarize_le_ratelimits(log_dir="/var/logs/letsencrypt",domains=[]):
    """Output information about rate limits with Let's Encrypt"""

    logs = list(glob.glob(log_dir+"/letsencrypt.log*"))
    logs.sort(key=natural_sorter)  # Put logs in the correct order

    # Convert domains to lowercase
    domains = [d.lower() for d in domains]

    sessions=find_recent_sessions(logs,hours=7*24)

    if summarize_dupe_certs(sessions,domains):
        print()

    if summarize_registered_domains(sessions,domains):
        print()

    sessions=find_recent_sessions(logs,hours=3)

    if summarize_failed_validations(sessions):
        pass

def main():
    parser = argparse.ArgumentParser(description="Read logs from certbot and summarize rate ban inforomation")
    parser.add_argument('--log_dir', metavar='PATH', type=str, nargs=1,
                    default=['/var/logs/letsencrypt'], help='Location of certbot logs (defaults to /var/logs/letsencrypt)')
    parser.add_argument('-d', '--domains', default=[], metavar='domain', nargs=1,
                    action='append', required=False, help='Domains to check in the logs')

    args = parser.parse_args()
    # Flatten the domain list
    domains = [d for l in args.domains for d in l]

    [log_dir] = args.log_dir

    summarize_le_ratelimits(log_dir,domains)

    sys.stdout.flush()
    sys.exit()

if __name__ == "__main__":
    main()


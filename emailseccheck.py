import validators.domain as validate_domain
import checkdmarc
from colorama import Fore
import os
import sys
import argparse


def initialize():
    parser = argparse.ArgumentParser(
        prog="emailseccheck.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    domain_argument_group = parser.add_mutually_exclusive_group(required=True)
    domain_argument_group.add_argument("--domain", type=str,
                                       help="Domain to check for SPF/DMARC issues")
    domain_argument_group.add_argument("--domains_file", type=str,
                                       help="File containing list of domains to check for SPF/DMARC issues")
    parser.add_argument("--json", type=str,
                                       help="Output results in JSON format")
    args = parser.parse_args()
    main(args)


def main(args):
    validate_args(args)

    domains_list = []

    if args.domain:
        domains_list.append(args.domain)
    else:
        with open(args.domains_file, "r") as domains_file:
            domains_file_content = domains_file.readlines()
            domains_list.extend(domains_file_content)

    domains_list = cleanup_domains_list(domains_list)

    if len(domains_list) > 0:
        results = check_domain_security(domains_list)
        
        if args.json:
            import json
            output = json.dumps(results, indent=2)
            
            with open(args.json, 'w') as f:
                f.write(output)
            
    else:
        print_error("No domain(s) were provided")


def cleanup_domains_list(domains_list):
    domains_list = [d.lower() for d in domains_list]
    domains_list = list(dict.fromkeys(domains_list))

    domains_list.sort()
    return domains_list


def validate_args(args):
    domain_arg_valid = args.domain is None or validate_domain(args.domain)
    domain_file_arg_valid = args.domains_file is None or os.path.isfile(
        args.domains_file)

    if not domain_arg_valid:
        print_warning("Domain is not valid. Is it formatted correctly?")
    elif not domain_file_arg_valid:
        print_warning("Domain file is not valid. Does it exist?")

    valid_args = domain_arg_valid and domain_file_arg_valid
    if not valid_args:
        print_error("Arguments are invalid.")
        sys.exit(1)

    return valid_args


def validate_provided_domains(domains):
    for domain in domains:
        if not validate_domain(domain):
            print_error("Invalid domain provided (%s)" % domain)
            sys.exit(1)


def check_domain_security(domains):
    print_info("Analyzing %d domain(s)..." % len(domains))

    spoofable_domains = []
    results = {
        "domains": {},
        "spoofable_domains": []
    }

    for domain in domains:
        domain = domain.strip()
        print_info("Analyzing %s" % domain)

        domain_result = {
            
            "spf_issues": [],
            "dmarc_issues": [],
            "spoofable": False
        }

        spoofing_possible_spf = False
        spoofing_possible_dmarc = False

        try:
            spf_results = checkdmarc.get_spf_record(domain)

            spf_value = spf_results["parsed"]["all"]

            if spf_value != 'fail':
                spoofing_possible_spf = True
                if spf_value == "softfail":
                    print_warning(
                        "SPF record configured to 'softfail' for '%s'" % domain)
                    domain_result["spf_issues"].append("SPF record configured to 'softfail'")
                else:
                    print_warning(
                        "SPF record missing failure behavior value for '%s'" % domain)
                    domain_result["spf_issues"].append("SPF record missing failure behavior value")
        except checkdmarc.DNSException:
            print_error(
                "A general DNS error has occured when performing SPF analysis")
            domain_result["spf_issues"].append("DNS error during SPF analysis")
        except checkdmarc.SPFIncludeLoop:
            print_warning(
                "SPF record contains an 'include' loop for '%s'" % domain)
            domain_result["spf_issues"].append("SPF record contains an 'include' loop")
        except checkdmarc.SPFRecordNotFound:
            print_warning("SPF record is missing for '%s'" % domain)
            domain_result["spf_issues"].append("SPF record is missing")
            spoofing_possible_spf = True
        except checkdmarc.SPFRedirectLoop:
            print_warning("SPF record contains a 'redirect' loop for '%s'" % domain)
            domain_result["spf_issues"].append("SPF record contains a 'redirect' loop")
        except checkdmarc.SPFSyntaxError:
            print_warning("SPF record contains a syntax error for '%s'" % domain)
            domain_result["spf_issues"].append("SPF record contains a syntax error")
            spoofing_possible_spf = True
        except checkdmarc.SPFTooManyDNSLookups:
            print_warning("SPF record requires too many DNS lookups for '%s'" % domain)
            domain_result["spf_issues"].append("SPF record requires too many DNS lookups")
        except checkdmarc.MultipleSPFRTXTRecords:
            print_warning("Multiple SPF records were found for '%s'" % domain)
            domain_result["spf_issues"].append("Multiple SPF records found")
            spoofing_possible_spf = True

        try:
            dmarc_data = checkdmarc.get_dmarc_record(domain)
        except checkdmarc.DNSException:
            print_error("A general DNS error has occured when performing DMARC analysis")
            domain_result["dmarc_issues"].append("DNS error during DMARC analysis")
        except checkdmarc.DMARCRecordInWrongLocation:
            print_warning("DMARC record is located in the wrong domain for '%s'" % domain)
            domain_result["dmarc_issues"].append("DMARC record is in wrong location")
        except checkdmarc.DMARCRecordNotFound:
            print_warning("DMARC record is missing for '%s'" % domain)
            domain_result["dmarc_issues"].append("DMARC record is missing")
            spoofing_possible_dmarc = True
        except checkdmarc.DMARCReportEmailAddressMissingMXRecords:
            print_warning("DMARC record's report URI contains a domain with invalid MX records for '%s'" % domain)
            domain_result["dmarc_issues"].append("DMARC report URI has invalid MX records")
        except checkdmarc.DMARCSyntaxError:
            print_warning("DMARC record contains a syntax error for '%s'" % domain)
            domain_result["dmarc_issues"].append("DMARC record contains a syntax error")
            spoofing_possible_dmarc = True
        except checkdmarc.InvalidDMARCReportURI:
            print_warning("DMARC record references an invalid report URI for '%s'" % domain)
            domain_result["dmarc_issues"].append("DMARC record has invalid report URI")
        except checkdmarc.InvalidDMARCTag:
            print_warning("DMARC record contains an invalid tag for '%s'" % domain)
            domain_result["dmarc_issues"].append("DMARC record contains invalid tag")
        except checkdmarc.MultipleDMARCRecords:
            print_warning("Multiple DMARC records were found for '%s'" % domain)
            domain_result["dmarc_issues"].append("Multiple DMARC records found")
            spoofing_possible_dmarc = True

        if spoofing_possible_spf or spoofing_possible_dmarc:
            spoofable_domains.append(domain)
            domain_result["spoofable"] = True
            results["spoofable_domains"].append(domain)

        results["domains"][domain] = domain_result

    if len(spoofable_domains) > 0:
        print(Fore.CYAN, "\n\n Spoofing possible for %d domain(s): " % len(spoofable_domains))
        for domain in spoofable_domains:
            print(Fore.CYAN, "  > %s" % domain)
    else:
        print(Fore.GREEN, "\n\n No spoofable domains were identified")

    return results


def print_error(message, fatal=True):
    print(Fore.RED, "[!] ERROR: %s" % message)
    if fatal:
        sys.exit(1)


def print_warning(message):
    print(Fore.YELLOW, "[-] WARN: %s" % message)


def print_info(message):
    print(Fore.LIGHTBLUE_EX, "[+] INFO: %s" % message)


if __name__ == "__main__":
    initialize()

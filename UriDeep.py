import argparse
import sys
import signal
from tld import get_tld
import idna
import socket
import whois
import os
from glob import glob
import json
import time

DESCRIPTION = ('UriDeep: Tool based on machine learning to create amazing fake domains using confusables. Some domains can deceive IDN policies')

CONFUSABLES_FULL = "./data/deepDiccConfusables.txt"
CONFUSABLES_LIGHT = "./data/confusables-table-light.txt"

def banner(delay_time=1):
    print("""
            _    ___
 /\ /\ _ __(_)  /   \___  ___ _ __
/ / \ \ '__| | / /\ / _ \/ _ \ '_ \\
\ \_/ / |  | |/ /_//  __/  __/ |_) |
 \___/|_|  |_/___,' \___|\___| .__/
                             |_|

 Version Beta
 Authors: Alfonso Muñoz (@mindcrypt)
          Miguel Hernández (@MiguelHzBz)
    """)
    time.sleep(delay_time)
def getArgs():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-d, --domain', action='store', dest='domain',
                        help='check similar domains to this one')
    parser.add_argument('-i', '--input', dest='fileinput',
                        help='List of targets. One input per line.')

    parser.add_argument('-F','--flipper', dest='flipper',default=False, nargs='?', const=True, type=bool, help='Execute flipping attack')
    parser.add_argument('-H','--homoglyph', dest='homoglyph',default=False, nargs='?',const=True, type=bool,help="Execute homoglyph attack with full table of confusables")
    parser.add_argument('-l', '--light', action='store_true', help='To create fake domains that could deceive IDN policies')
    parser.add_argument('-S','--substitution', dest='substitution',default=False, nargs='?', const=True, type=bool, help="Execute substitution attack")

    parser.add_argument('-c', '--check', action='store_true',
                        help='check if this domain is alive')


    parser.add_argument('-w', '--whois', action='store_true',dest='whois',
                        help='check whois')

    parser.add_argument('-vt', '--virustotal', action='store_true',dest='virustotal',
                        help='check Virus Total')
    parser.add_argument('-key', '--api-key', dest='api',
                        help='VirusTotal API Key')

    parser.add_argument('-o', '--output', dest='outputfile', help='Output file')


    args = parser.parse_args()
    testArgs(args,parser)
    return args

def testArgs(args,parser):
    if (not args.domain and not args.fileinput):
        print(parser.print_help())
        print("Need one type of input, {-i --input} or {-d --domain}")
        sys.exit(-1)

    if(args.virustotal and not args.api):
        print('Please, enter a VirusTotal API Key with -api or --api-key')
        sys.exit(-1)

    if not (args.homoglyph or args.substitution or args.flipper):
        print(parser.print_help())
        print("Need one type of attack, {-F --flipper} {-H --homoglyph} or {-S --substitution}")
        sys.exit(-1)
    if args.fileinput:
        try:
            f = open(args.fileinput, 'r')
            f.close()
        except Exception:
            print(parser.print_help())
            print("--------------\n\n")
            print("Wrong input file.\n\n")
            print("--------------")
            sys.exit(-1)
    if (args.outputfile):
        try:
            f = open(args.outputfile, 'w')
            f.close()
        except Exception:
            print("--------------")
            print("Wrong output file.\n\n")
            print("--------------")
            print(parser.print_help())
            sys.exit(-1)

def read_data(filename):
   with open(filename, 'r') as f:
       lines = f.readlines()
   return lines

def who_is(domain):
    try:
        return whois.whois(domain)
    except whois.parser.PywhoisError:
        print('Whois not found!')
        return('Whois not found!')
    except:
        return ('Whois timeout')

def read_domain(domain):
    res = get_tld(domain, as_object=True, fix_protocol=True)
    return res

def read_confusables(filename):
    lines, confusables = [], {}
    with open(filename, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    for line in lines:
        characters = list(line.replace('\n', ''))
        latin_character = characters[0]
        confusables[latin_character] = characters
    return confusables

def generate_flipper_domains(dom):

    domain = dom.domain
    new_urls_without_letter = []
    n = 0
    m = len(domain)

    if m == 1:
        new_urls_without_letter.append(domain)
    elif m == 2:
        new_domain = domain[1] + domain[0]
        new_urls_without_letter.append(new_domain)

    else:

        while n < m and m > 2:

            if n == 0 :
                new_domain = domain[n + 1] + domain[n] + domain[n + 2:m]

            elif n == 1:
                new_domain = domain[0] + domain[n + 1] + domain[n] + domain[n + 2:m]

            elif 1 < n < m - 1:
                new_domain = domain[0:n] + domain[n + 1] + domain[n] + domain[n + 2:m]

            n = n + 1
            new_urls_without_letter.append(new_domain+"."+dom.tld)
    new_urls_list = list(set(new_urls_without_letter))
    return new_urls_list

def generate_substitution_domains(dom):
    domain = dom.domain

    new_urls_with_double_letter = []
    n = 0
    m = len(domain)
    while n < m:
        new_domain = domain[0:n] + domain[n] + domain[n] + domain[n+1:m]
        new_urls_with_double_letter.append(new_domain+"."+dom.tld)
        new_domain = domain[0:n] + domain[n+1:m]
        new_urls_with_double_letter.append(new_domain+"."+dom.tld)
        n = n + 1
    new_urls_list = list(set(new_urls_with_double_letter))
    return new_urls_list

def change(res, i, confusables):
    domain = res.domain
    subdomain = res.subdomain
    tld = res
    domains = []
    if domain[i] in confusables:
        for c in confusables[domain[i]]:
            new_domain = list(domain)
            new_domain[i] = c
            if(subdomain):
                domains.append('{}.{}.{}'.format(subdomain, ''.join(new_domain), tld))
            else:
                domains.append('{}.{}'.format(''.join(new_domain), tld))

    return domains


def similar_domains(res, confusables):
    domain = res.domain
    domains = []
    for i, c in enumerate(domain):
        domains.extend(change(res, i, confusables))
    return set(domains)

def to_punnycode(domain):
    try:
        return domain.encode("idna")
    except Exception as e:
        pass

def is_alive(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except Exception as e:
        return False

def to_punnycode_array(domains):
    return list(filter(None, [to_punnycode(x) for x in domains]))

def main():
    banner(1)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    args = getArgs()
    idomains = list()
    if args.domain:
        idomains.append(args.domain)
    else:
        lines = read_data(args.fileinput)
        for line in lines:
                idomains.append(line.strip())
    d_salida = {'result':[]}
    for domain in idomains:
        domain_list = []
        print('Domain target: ' + domain)
        dom = read_domain(domain)
        if args.homoglyph:
            print('Option selected: Homoglyph attack')
            if args.light:
                print('Option selected: Lite confusables')
                confusables = read_confusables(CONFUSABLES_LIGHT)
            else:
                print('Option selected: Full confusables')
                confusables = read_confusables(CONFUSABLES_FULL)
            print('Generate similar domains...')
            domains_h = set(similar_domains(dom, confusables))
            domain_list.extend(domains_h)
        if args.flipper:
            print('Option selected: Flipping attack')
            print('Generate similar domains...')
            domains_f = set(generate_flipper_domains(dom))
            domain_list.extend(domains_f)
        if args.substitution:
            print('Option selected: Substitution attack')
            print('Generate similar domains...')
            domains_s = set(generate_substitution_domains(dom))
            domain_list.extend(domains_s)
        if len(domain_list) > 0:
            print('Similars domains to {}: {}'.format(dom.domain,len(domain_list)))
            for punnydomain in domain_list:
                s = {'domain':punnydomain}
                s["domain_punnycode"] = to_punnycode(punnydomain)
                if(args.check and is_alive(punnydomain)):
                    s["active"] = True
                    if args.whois:
                        print("Check Whois: {}".format(punnydomain.decode("utf-8")))
                        w = who_is(punnydomain.decode("utf-8"))
                        s["whois"] = w
                    if args.virustotal:
                        print("Check Virus Total: {}".format(punnydomain.decode("utf-8")))
                        vt = VirusTotalPublicApi(API_KEY)
                        response = vt.get_url_report('https://{}'.format(punnydomain.decode("utf-8")), scan='1')
                        json_vt = (json.dumps(response, sort_keys=False, indent=4))
                        s["virustotal"] = json_vt
                d_salida["result"].append(s)
            if args.outputfile:
                print("\n")
                print("******************************************************")
                print("Outputfile with the summary: {}".format(args.outputfile))
                with open(args.outputfile, 'w') as outfile:
                    json.dump(d_salida, outfile,default=str)
            else:
                for j in d_salida["result"]:
                    print(j)

if __name__ == '__main__':
    main()

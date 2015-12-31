#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Chen Lei
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import pkgutil
import base64
import datetime
import sys
import socket
import re
from argparse import ArgumentParser

__all__ = ['main']

gfwlist_url = 'https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt'

def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-i', '--input', dest='input', required=False,
            help='path to gfwlist file, raw url or local path,'\
                    ' default will get from gfwlist github repo',
            metavar='gfwlist.txt')
    parser.add_argument('-o', '--output', dest='output', required=False,
            help='path to output dnsmasq.conf, default will write to'\
                    '  dnsmasq.conf in current directory',
            default = './dnsmasq.conf', metavar='dnsmasq.conf')
    parser.add_argument('-s', '--server', dest='server', required=False,
            help='The upstream dns server address for the poisoned domain,'\
                    ' default value is 127.0.0.1',
            default='127.0.0.1', metavar='server')
    parser.add_argument('-p', '--port', dest='port', required=False,
            type=int, choices=range(1, 65535), default=5353,
            help='The upstream dns server port for the poisoned domain,'\
                    ' default value is 5353',
            metavar='port')
    parser.add_argument('-e', '--ipset', dest='ipset', required=False,
            help='ipset name of the dnsmasq ipset, ipset not support if'\
                    ' not presented',
            metavar='ipsetname')
    return parser.parse_args()


def decode_gfwlist(content):
    # decode base64 if have to
    try:
        return base64.b64decode(content)
    except:
        return content


def get_hostname(something):
    try:
        # quite enough for GFW
        if not something.startswith('http:'):
            something = 'http://' + something
        try:
            from urllib.parse import urlparse
        except ImportError:
            from urlparse import urlparse
        r = urlparse(something)
        return r.hostname
    except Exception as e:
        logging.error(e) 
        return None

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_domain(domain):
    if len(domain) > 255:
        return False
    if domain[-1] == ".":
        domain = domain[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in domain.split("."))


def add_domain_to_set(s, something):
    hostname = get_hostname(something)
    if hostname is not None:
        if hostname.startswith('.'):
            hostname = hostname.lstrip('.')
        if hostname.endswith('/'):
            hostname = hostname.rstrip('/')
        if is_valid_ipv4_address(hostname):
            return
        if not is_valid_domain(hostname):
            return
        if hostname:
            s.add(hostname)


def parse_gfwlist(content):
    builtin_rules = pkgutil.get_data('gfwlist2dnsmasq', 'resources/builtin.txt').decode().splitlines(False)
    gfwlist = content.decode().splitlines(False)
    domains = set(builtin_rules)
    for line in gfwlist:
        if line.find('.*') >= 0:
            continue
        elif line.find('*') >= 0:
            line = line.replace('*', '/')
        if line.startswith('!'):
            continue
        elif line.startswith('['):
            continue
        elif line.startswith('@'):
            # ignore white list
            continue
        elif line.startswith('||'):
            add_domain_to_set(domains, line.lstrip('||'))
        elif line.startswith('|'):
            add_domain_to_set(domains, line.lstrip('|'))
        elif line.startswith('.'):
            add_domain_to_set(domains, line.lstrip('.'))
        else:
            add_domain_to_set(domains, line)
    return domains

def generate_dnsmasq(domains, args):
    with open(args.output, 'w') as of:
        of.write('# gfwlist dnsmasq rule generated by gfwlist2dnsmasq\n')
        of.write('# updated on ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '\n')
        of.write('# bug report: https://github.com/mysqto/gfwlist2dnsmasq\n\n')
        domains = sorted(domains)
        for domain in domains:
            if args.port == 53:
                of.write('server=/.%s/%s\n'%(domain, args.server))
            else:
                of.write('server=/.%s/%s#%d\n'%(domain, args.server, args.port))
            if args.ipset:
                of.write('ipset=/.%s/%s\n'%(domain, args.ipset))
    of.close()

def main():
    args = parse_args()
    try:
        with open(args.input, 'rb') as f:
            content = f.read()
    except:
        try:
            try:
                from urllib.request import urlopen
            except ImportError:
                from urllib2 import urlopen
            content = urlopen(gfwlist_url, timeout = 15).read()
        except:
            import traceback            
            print(traceback.format_exc())
            print('Error, cannot download gfwlist from repo, please specify one.')
            sys.exit(-1)
    content = decode_gfwlist(content)
    domains = parse_gfwlist(content)
    generate_dnsmasq(domains, args)
        
if __name__ == '__main__':
    main()

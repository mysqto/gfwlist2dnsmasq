# gfwlist2dnsmasq
Convert gfwlist to dnsmasq.conf with ipset supported inspired by gfwlist2pac

```
usage: main.py [-h] [-i gfwlist.txt] [-u user_rule.txt] [-o dnsmasq.conf]
               [-s server] [-p port] [-e ipsetname]

optional arguments:
  -h, --help            show this help message and exit
  -i gfwlist.txt, --input gfwlist.txt
                        path to gfwlist file, raw url or local path, default
                        will get from gfwlist github repo
  -u user_rule.txt, --user-rule user_rule.txt
                        customized user rule, which will be append to gfwlist
                        raw url or local path
  -o dnsmasq.conf, --output dnsmasq.conf
                        path to output dnsmasq.conf, default will write to
                        dnsmasq.gfwlist.conf in current directory
  -s server, --server server
                        The upstream dns server address for the poisoned
                        domain, default value is 127.0.0.1
  -p port, --port port  The upstream dns server port for the poisoned domain,
                        default value is 5353
  -e ipsetname, --ipset ipsetname
                        ipset name of the dnsmasq ipset, ipset not support if
                        not presented
```

# NsDeeper

Tool for subdomains search in-deep. Got list of top-level domains, and already known 
subdomains from you. For every target using assetfinder/subfinder/alterx/shuffledns.

Technically, it's just a wrapper for these utilities.

Use -h for see all params. Example:
```
./nsdeeper.py -d top-level-domains.txt -s already-known-subdomains.txt -w dict-for-brute.txt -t 500 
```

## Install
```
pip3 install dnspython tld randstr
```

And tools: subfinder, assetfinder, alterx, shuffledns.
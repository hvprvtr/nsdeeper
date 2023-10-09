
DOMAIN_SOURCE_SUBFINDER = "subfinder"
DOMAIN_SOURCE_ASSETFINDER = "asstetfinder"
DOMAIN_SOURCE_ALTERX = "alterx"
DOMAIN_SOURCE_BRUTEFORCE = "bruteforce"

DOMAIN_SOURCE_POSSIBLES = [
    DOMAIN_SOURCE_SUBFINDER,
    DOMAIN_SOURCE_ASSETFINDER,
    DOMAIN_SOURCE_ALTERX,
    DOMAIN_SOURCE_BRUTEFORCE
]

DOMAIN_SOURCE_TRUSTS = {
    DOMAIN_SOURCE_SUBFINDER: True,
    DOMAIN_SOURCE_ASSETFINDER: True,
    DOMAIN_SOURCE_ALTERX: False,
    DOMAIN_SOURCE_BRUTEFORCE: False
}


class Domain(object):
    domain = ""
    parent = ""
    source = ""
    trusted = False
    wildcard = False
    parent_wildcard = False
    checked = False

    def __init__(self, domain, source, wildcard, parent_wildcard):
        if source not in DOMAIN_SOURCE_POSSIBLES:
            raise Exception("Unknown domain source - {0} => {1}".format(domain, source))

        self.domain = domain
        self.source = source
        self.trusted = DOMAIN_SOURCE_TRUSTS[source]
        self.wildcard = wildcard
        self.parent_wildcard = parent_wildcard

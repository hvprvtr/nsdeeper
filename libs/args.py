import argparse

from libs.Config import Config


def params_parse():
    parser = argparse.ArgumentParser(description='Subdomains search in-deep.')

    parser.add_argument('-sp', '--subfinder-path', help="Subfinder path", default="/usr/bin/subfinder")
    parser.add_argument('-ap', '--assetfinder-path', help="Assetfinder path",
                        default="/usr/bin/assetfinder")
    parser.add_argument('-xp', '--alterx-path', help="Alterx path", default="/usr/local/bin/alterx")
    parser.add_argument('-fp', '--shuffledns-path', help="Shuffledns path.",
                        default="/usr/local/bin/shuffledns")

    parser.add_argument('-f', '--finds-file', help="Where to write finds.", default="finds.txt")
    parser.add_argument('-w', '--wordlist', help="Wordlist for bruteforce", required=True)
    parser.add_argument('-d', '--top-domains', help="Top-level target domains", required=True) #TODO one, comma separated or file - everythere in params where it is possible
    parser.add_argument('-s', '--subdomains', help="Already known subdomains",
                        required=False, default=None)
    parser.add_argument('-l', '--log', help="Log file", default="log.txt")
    parser.add_argument('-ll', '--log-level', help="Log level", default="info",
                        choices=Config.possible_log_levels)
    parser.add_argument('-r', '--resolvers', help="File with resolvers", default="resolvers.txt")

    parser.add_argument('-t', '--threads', help="Threads count", default=250, type=int)
    parser.add_argument('-brl', '--bruteforce-results-limit',
                        help="If more, the results of bruteforce will be ignored.", default=100,
                        type=int)
    parser.add_argument('-tr', '--trusted-resolvers', help="Trusted resolvers IP, comma separated.",
                        default="1.1.1.1,8.8.8.8,8.8.4.4", type=str)
    parser.add_argument('-sr', '--stop-results-cnt',
                        help="Stop work immediately if domains queue will be more than.",
                        default=2000, type=int)

    args = parser.parse_args()
    return args

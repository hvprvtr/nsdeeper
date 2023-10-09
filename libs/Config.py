import os 
import re 
import logging
import sys


class Config:
    stop_results_cnt = None
    
    subfinder_path = None
    assetfinder_path = None
    alterx_path = None
    shuffledns_path = None
    
    resolvers_list_path = None
    wordlist_path = None
    top_level_domains_file = None

    known_subdomains_file = None
    
    finds_file = None

    threads_limit = None

    results_limit = None

    trusted_resolvers = None

    possible_log_levels = ['debug', 'info']

    log_level = "info"

    log_file = None

    logger = None

    tmp_dir = None #TODO param tmp-dir
    
    @staticmethod
    def init(args):
        Config.stop_results_cnt = args.stop_results_cnt

        Config.subfinder_path = args.subfinder_path
        if not os.path.exists(Config.subfinder_path):
            print("Subfinder not found in " + Config.subfinder_path + ". Install it or set by -sp/--subfinder-path.")
            exit(1)

        Config.assetfinder_path = args.assetfinder_path
        if not os.path.exists(Config.assetfinder_path):
            print("Assetfinder not found in " + Config.assetfinder_path + ". Install it or set by -ap/--assetfinder-path.")
            exit(1)

        Config.alterx_path = args.alterx_path
        if not os.path.exists(Config.alterx_path):
            print("Alterx not found in " + Config.alterx_path + ". Install it or set by -xp/--alterx-path.")
            exit(1)

        Config.shuffledns_path = args.shuffledns_path
        if not os.path.exists(Config.shuffledns_path):
            print("Shuffledns not found in " + Config.shuffledns_path + ". Install it or set by -fp/--shuffledns-path.")
            exit(1)

        Config.resolvers_list_path = args.resolvers
        if not os.path.exists(Config.resolvers_list_path):
            print("Resolvers file not exists: " + Config.resolvers_list_path)
            exit(1)

        Config.wordlist_path = args.wordlist
        if not os.path.exists(Config.wordlist_path):
            print("Wordlist not exists: " + Config.wordlist_path)
            exit(1)

        Config.top_level_domains_file = args.top_domains

        Config.known_subdomains_file = args.subdomains
        if len(Config.known_subdomains_file) and not os.path.exists(Config.known_subdomains_file):
            print("Subdomains file not exists: " + Config.known_subdomains_file)
            exit(1)

        Config.finds_file = args.finds_file

        Config.threads_limit = args.threads

        Config.results_limit = args.bruteforce_results_limit

        Config.trusted_resolvers = list(map(str.strip, args.trusted_resolvers.split(",")))

        for resolver_ip in Config.trusted_resolvers:
            if re.match('^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', resolver_ip):
                continue
            print("Error: Bad resolver IP: " + resolver_ip)
            exit(1)

        if args.log_level not in Config.possible_log_levels:
            print("Error: Wrong log level: {0}. Possible: {1}".format(
                args.log_level, ",".join(Config.possible_log_levels)))
            exit(1)

        Config.log_level = logging.INFO
        if args.log_level == "debug":
            Config.log_level = logging.DEBUG

        logging.basicConfig(filename=Config.log_file,
                            filemode='a',
                            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                            datefmt='%H:%M:%S',
                            level=Config.log_level)
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
        Config.logger = logging.getLogger()

        Config.tmp_dir = os.path.realpath((os.path.dirname(os.path.realpath(__file__)) + "/../tmp/")) + "/"

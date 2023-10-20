#!/usr/bin/python3

import queue
import time

from libs.common import *
from libs.tools import *
from libs.args import *
from libs.Config import Config

args = params_parse()
Config.init(args)

logger = Config.logger

domains = set()
if os.path.exists(Config.top_level_domains_file):
    domains.update(file_to_set_specific(Config.top_level_domains_file))
else:
    domains.add(Config.top_level_domains_file)

if Config.known_subdomains_file != "":
    domains.update(file_to_set_specific(Config.known_subdomains_file))
logger.info("We got {0} targets for deeping".format(len(domains)))

q = queue.Queue()
for d in domains:
    q.put(d)

stime_full = int(time.time())
checked_domains = set()
while True:
    if q.qsize() > Config.stop_results_cnt:
        logger.critical("Queue size now: {qs}. This is more than limit: {l}. "
                        "Something going wrong. If you need, change limit by -sr/--stop-results-cnt "
                        "param".format(qs=q.qsize(), l=Config.stop_results_cnt))
        exit(1)

    try:
        target_domain = q.get(False)
        if target_domain in checked_domains:
            logger.info("Domain {0} is already checked, skip it.".format(target_domain))
            continue

        checked_domains.add(target_domain)

        new_cnt = 0
        logger.info("Start working with {0} / {1} left".format(target_domain, q.qsize()))
        stime = int(time.time())

        new_cnt += block_subfinder(target_domain, domains, checked_domains, q)
        new_cnt += block_assetfinder(target_domain, domains, checked_domains, q)
        new_cnt += block_alterx(target_domain, domains, checked_domains, q)

        if is_domain_wildcard(target_domain):
            logger.info("Domain {0} is wildcard, skip it".format(target_domain))
            continue
        else:
            logger.info("Domain {0} is not wildcard, continue".format(target_domain))

        new_cnt += block_bruteforce(target_domain, domains, checked_domains, q)

        etime = int(time.time())
        work_time = etime - stime

        logger.info("Brute of {domain} got {cnt} new domains".format(domain=target_domain, cnt=new_cnt))
        logger.info("Work time left for current queue: ~" + secs_to_text(work_time * q.qsize()))
    except queue.Empty:
        break

etime_full = int(time.time())
logger.info("We done for {0}".format(secs_to_text(etime_full-stime_full)))

#TODO общее число найденного в конце
#TODO speedup - if domains resolvers is different (by top-level and IP) - works parallel
#TODO tools exists checking
#TODO end of work - see errors cnt, check log
#TODO save session by domains list md5 and wordlist md5, restore by param
#TODO altdns to
#TODO founds => json output with tool source, чтоб понмать откуда взят сабдомен
#TODO check subdomains from top domain
#TODO Done time AVG based - by all done to this moment
#TODO finally csv with sources of domains (subfinder - may show sources? VT, etc)
#TODO good logging
#TODO sessions mechanism
#TODO valid check - 1.1.1.1 or original nss
#TODO лимит на кол-во результатов поиска - не отловленный вилдкард
#TODO alive finally check
#TODO results logging?
#TODO start check all domains by NS got. Help if wrong domain or file specified.

#TODO start domains check + disable it by param
#TODO разный логгинг идёт в stdout, разобраться почему
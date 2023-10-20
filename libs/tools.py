import os
import re
import subprocess
import dns.resolver

from randstr import randstr

from libs.Config import Config
from libs.common import get_top_level_domain, get_lines_cnt


wildcard_cache = {} #TODO хранить всегда, инвалидация в ТУДУ. Обдумать, может закешироваться шлак.
def is_domain_parent_is_wildcard(domain):
    top_domain = get_top_level_domain(domain)
    if top_domain == domain:
        parent_for_check = domain
    else:
        parent_for_check = domain.split(".", 1)[1]

    if parent_for_check in wildcard_cache.keys():
        return wildcard_cache[parent_for_check]

    result = is_domain_wildcard(parent_for_check)

    wildcard_cache[parent_for_check] = result

    return result


def is_domain_wildcard(domain): #TODO multithreading in start of work
    resolved_cnt = 0
    for _ in range(2):#TODO in config/params
        result = is_domain_alive(randstr(10) + "." + domain)
        resolved_cnt += 1 if result else 0
    return resolved_cnt == 2


def is_domain_alive(domain):
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = Config.trusted_resolvers
    try:
        my_resolver.resolve(domain, tcp=True)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoNameservers:
        return False  # TODO retest, log?
    except dns.resolver.LifetimeTimeout:
        return False #TODO retest, log?
    except dns.resolver.NoAnswer:
        Config.logger.error("Domain {0}, no answer in DNS response.".format(domain))
        return False


def is_domain_valid(domain):
    result = bool(re.match('^[a-z0-9\-_\.]+$', domain, re.I))
    if not result:
        Config.logger.error("Invalid domain: {0}".format(domain))
    return result


def run_assetfinder(target_domain):
    try:
        output_file = Config.tmp_dir + target_domain + "-asstefinder.out"
        if os.path.exists(output_file):
            return output_file
        cmd = [
            Config.assetfinder_path,
            "--subs-only",
            target_domain,
        ]
        Config.logger.debug("Assetfinder cmd for domain {d}: {c}".format(
            d=target_domain, c=" ".join(cmd)))
        # print(" ".join(cmd))
        output = subprocess.run(cmd, capture_output=True)
        with open(output_file, "w") as fh:
            fh.write(output.stdout.decode())

        return output_file
    except subprocess.CalledProcessError as e:
        print('Exception: \n Cmd: {cmd}\nOutput: {output}'.format(
            cmd=" ".join(cmd), output=e.stdout))
        exit(0) #TODO точно?


def run_subfinder(target_domain):
    try:
        output_file = Config.tmp_dir + target_domain + "-subfinder.out"
        if os.path.exists(output_file):
            return output_file
        cmd = [
            Config.subfinder_path,
            "-d", target_domain,
            "-o", output_file,
        ]
        Config.logger.debug("Subfinder cmd for domain {d}: {c}".format(
            d=target_domain, c=" ".join(cmd)))
        output = subprocess.run(cmd, capture_output=True) #TODO проверить нормально ли тут записывается аутпут
        with open(output_file, "w") as fh:
            fh.write(output.stdout.decode())

        return output_file
    except subprocess.CalledProcessError as e:
        print('Exception: \n Cmd: {cmd}\nOutput: {output}'.format(
            cmd=" ".join(cmd), output=e.stdout))
        exit(0) #TODO точно?


def run_bruteforce(target_domain):
    try:
        output_file = Config.tmp_dir + target_domain + "-bruteforce.out"
        if os.path.exists(output_file):
            return output_file
        cmd = [
            Config.shuffledns_path,
            "-t", str(Config.threads_limit),
            "-d", target_domain,
            "-w", Config.wordlist_path,
            "-o", output_file,
            "-r", str(Config.resolvers_list_path),
        ]
        Config.logger.debug("Bruteforce cmd for domain {d}: {c}".format(d=target_domain, c=" ".join(cmd)))
        output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        return output_file
    except subprocess.CalledProcessError as e:
        print('Exception: \n Cmd: {cmd}\nOutput: {output}'.format(
            cmd=" ".join(cmd), output=e.stdout))
        exit(0) #TODO точно?


def build_alterx_list(target_domain):
    try:
        output_file = Config.tmp_dir + target_domain + "-alterx.out"
        if os.path.exists(output_file):
            return output_file
        cmd = [
            Config.alterx_path,
            "-l", target_domain,
            "-o", output_file,
        ]
        Config.logger.debug("Alterx cmd for domain {d}: {c}".format(
            d=target_domain, c=" ".join(cmd)))
        output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return output_file
    except subprocess.CalledProcessError as e:
        print('Exception: \n Cmd: {cmd}\nOutput: {output}'.format(
            cmd=" ".join(cmd), output=e.stdout))
        exit(0) #TODO точно?


def check_alterx_results(target_domain, alterx_output_file):
    try:
        output_file = Config.tmp_dir + target_domain + "-alterx-check.out"
        if os.path.exists(output_file):
            return output_file
        cmd = [
            Config.shuffledns_path,
            "-t", str(Config.threads_limit),
            "-d", get_top_level_domain(target_domain),
            "-l", alterx_output_file,
            "-o", output_file,
            "-r", str(Config.resolvers_list_path),
        ]
        Config.logger.debug("Shuffledns/Alterx cmd for domain {d}: {c}".format(d=target_domain, c=" ".join(cmd)))
        output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        return output_file
    except subprocess.CalledProcessError as e:
        print('Exception: \n Cmd: {cmd}\nOutput: {output}'.format(
            cmd=" ".join(cmd), output=e.stdout))
        exit(0) #TODO точно?


def block_subfinder(target_domain, domains, checked_domains, q):
    output_file = run_subfinder(target_domain)
    lines_cnt = get_lines_cnt(output_file)
    Config.logger.info("Subfinder got {0} lines in result {1}. Domain {2}".format(
        lines_cnt, output_file, target_domain))
    new_cnt = process_tool_result(output_file, domains, checked_domains, q, True)
    return new_cnt


def block_assetfinder(target_domain, domains, checked_domains, q):
    output_file = run_assetfinder(target_domain)
    lines_cnt = get_lines_cnt(output_file)
    Config.logger.info("Assetfinder got {0} lines in result {1}. Domain {2}".format(
        lines_cnt, output_file, target_domain))
    new_cnt = process_tool_result(output_file, domains, checked_domains, q, True)
    return new_cnt


def block_bruteforce(target_domain, domains, checked_domains, q):
    output_file = run_bruteforce(target_domain)
    lines_cnt = get_lines_cnt(output_file)
    Config.logger.info("Bruteforce got {0} lines in result {1}. Domain {2}".format(
        lines_cnt, output_file, target_domain))
    if lines_cnt >= Config.results_limit:
        Config.logger.warning(
            "Too many lines in bruteforce result {0}. {1} vs {2}. Skip it. See manually.".format(
                output_file, lines_cnt, Config.results_limit))
        return 0
    new_cnt = process_tool_result(output_file, domains, checked_domains, q)
    return new_cnt


def block_alterx(target_domain, domains, checked_domains, q):
    alterx_output_file = build_alterx_list(target_domain)
    output_file = check_alterx_results(target_domain, alterx_output_file)
    lines_cnt = get_lines_cnt(output_file)
    if lines_cnt >= Config.results_limit:
        Config.logger.warning(
            "Too many lines in alterx check result {0} (source = {3}). {1} vs {2}. "
            "Skip it. See manually.".format(
                output_file, lines_cnt, Config.results_limit, alterx_output_file))
        return 0
    new_cnt = process_tool_result(output_file, domains, checked_domains, q)
    return new_cnt


def process_tool_result(output_file, domains, checked_domains, q, trusted=False):
    new_cnt = 0
    with open(output_file) as fh:
        for domain_candidate in fh:
            domain_candidate = domain_candidate.strip().lower()
            if not len(domain_candidate):
                continue

            if not is_domain_valid(domain_candidate):
                continue

            if domain_candidate in domains or \
                    domain_candidate in checked_domains:
                continue

            domain_alive = is_domain_alive(domain_candidate)
            Config.logger.info("Domain {0} is alive: {1}".format(domain_candidate, domain_alive))
            if not domain_alive:
                continue

            if not trusted and is_domain_parent_is_wildcard(domain_candidate):
                Config.logger.info("Parent of {0} is wildcard, skip it.".format(domain_candidate))
                continue

            new_cnt += 1
            with open(Config.finds_file, "a") as finds_fh:
                Config.logger.info("Adding {0} to finds".format(domain_candidate))
                finds_fh.write(domain_candidate + "\n")

            domains.add(domain_candidate)
            q.put(domain_candidate)
    return new_cnt
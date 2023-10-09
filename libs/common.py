from tld import get_tld


def get_lines_cnt(fpath):
    count = 0
    with open(fpath, 'r') as fh:
        for _ in fh:
            count += 1
    return count


def secs_to_text(secs):
    """ Convert number of seconds to human string - *d*h*m*s """
    secs = int(secs)

    min_time = 60
    hour_time = 3600
    day_time = 3600*24

    days = 0
    hours = 0
    mins = 0

    if secs >= day_time:
        days = int(secs / day_time)
        secs = secs % day_time

    if secs >= hour_time:
        hours = int(secs / hour_time)
        secs = secs % hour_time

    if secs >= min_time:
        mins = int(secs / min_time)
        secs = secs % min_time

    str_time = []
    if days:
        str_time.append("{0}d".format(days))
    if hours:
        str_time.append("{0}h".format(hours))
    if mins:
        str_time.append("{0}m".format(mins))

    if not len(str_time) or secs > 0:
        str_time.append("{0}s".format(secs))

    return " ".join(str_time)


def file_to_set(fpath):
    result = set()
    with open(fpath) as fh:
        for line in fh:
            line = line.strip()
            if not len(line) or line.startswith("#"):
                continue
            result.add(line)
    return result


def get_top_level_domain(domain):
    tld = get_tld("http://" + domain)
    level_two = domain[:-len(tld)-1].split('.')[-1]
    return level_two + "." + tld
import re

def is_ip(q):
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", q))

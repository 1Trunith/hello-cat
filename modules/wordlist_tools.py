import gzip
import os
import re
import shutil
import tempfile

ROCKYOU_CANDIDATES = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.gz",
]

SECLISTS_USERNAME_CANDIDATES = [
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "/usr/share/seclists/Usernames/Names/names.txt",
    "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
]

_ROCKYOU_CACHE = os.path.join(tempfile.gettempdir(), "hello_cat_rockyou_cache.txt")


def _decompress_gz(gz_path, dest_path):
    if os.path.isfile(dest_path):
        return dest_path
    with gzip.open(gz_path, "rb") as src, open(dest_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return dest_path


def resolve_password_source(custom_path=None):
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for candidate in ROCKYOU_CANDIDATES:
        if candidate.endswith(".gz") and os.path.isfile(candidate):
            return _decompress_gz(candidate, _ROCKYOU_CACHE)
        if os.path.isfile(candidate):
            return candidate
    return None


def resolve_username_source(custom_path=None):
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for candidate in SECLISTS_USERNAME_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return None


def iter_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield line


def count_lines(path, cap=None):
    count = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if line.strip():
                count += 1
                if cap and count >= cap:
                    return count
    return count


CREDENTIAL_PATTERNS = [
    re.compile(r"([A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+)\s*[:,|]\s*(\S+)"),
    re.compile(r"(?i)\buser(?:name)?\s*[:=]\s*(\S+)\s+pass(?:word)?\s*[:=]\s*(\S+)"),
    re.compile(r"^([A-Za-z0-9_.-]{3,32}):(\S{3,})$", re.MULTILINE),
]

COMMON_SUFFIXES = ["", "1", "12", "123", "1234", "!", "!!", "@", "#",
                    "2023", "2024", "2025", "01", "007"]
LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}


def load_list(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh if line.strip()]


def save_list(words, path):
    with open(path, "w", encoding="utf-8") as fh:
        for word in words:
            fh.write(word + "\n")


def merge_lists(paths):
    merged = []
    seen = set()
    for path in paths:
        for word in load_list(path):
            if word not in seen:
                seen.add(word)
                merged.append(word)
    return merged


def dedupe(words):
    seen = set()
    result = []
    for word in words:
        if word not in seen:
            seen.add(word)
            result.append(word)
    return result


def filter_by_length(words, min_len=None, max_len=None):
    return [w for w in words if (min_len is None or len(w) >= min_len)
            and (max_len is None or len(w) <= max_len)]


def filter_by_pattern(words, pattern):
    regex = re.compile(pattern)
    return [w for w in words if regex.search(w)]


def leetspeak_variant(word):
    return "".join(LEET_MAP.get(c.lower(), c) for c in word)


def generate_password_variants(base_words, include_leet=True, include_years=True):
    variants = set()
    years = [str(y) for y in range(2015, 2027)] if include_years else []
    suffixes = COMMON_SUFFIXES + years

    for word in base_words:
        for cap in (word, word.capitalize(), word.upper(), word.lower()):
            variants.add(cap)
            for suffix in suffixes:
                variants.add(cap + suffix)
            if include_leet:
                leet = leetspeak_variant(cap)
                variants.add(leet)
                for suffix in suffixes:
                    variants.add(leet + suffix)
    return sorted(variants)


def generate_usernames(first_name, last_name, extra_words=None):
    first_name = first_name.lower().strip()
    last_name = last_name.lower().strip()
    f, l = first_name[:1], last_name[:1]
    variants = {
        first_name, last_name,
        f"{first_name}.{last_name}", f"{first_name}_{last_name}",
        f"{first_name}{last_name}", f"{f}{last_name}", f"{first_name}{l}",
        f"{last_name}.{first_name}", f"{last_name}{first_name}",
        f"{last_name}_{first_name}", f"{f}.{last_name}",
    }
    if extra_words:
        for word in extra_words:
            variants.add(word.lower())
            variants.add(f"{first_name}.{word.lower()}")
    return sorted(v for v in variants if v)


def extract_credentials(text):
    found = []
    for pattern in CREDENTIAL_PATTERNS:
        for match in pattern.finditer(text):
            found.append({"username": match.group(1), "password": match.group(2)})
    seen = set()
    unique = []
    for cred in found:
        key = (cred["username"], cred["password"])
        if key not in seen:
            seen.add(key)
            unique.append(cred)
    return unique


def extract_credentials_from_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return extract_credentials(fh.read())

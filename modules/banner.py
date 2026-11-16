try:
    import colorama
    colorama.init(autoreset=True)
    _CYAN = colorama.Fore.CYAN
    _MAGENTA = colorama.Fore.MAGENTA
    _YELLOW = colorama.Fore.YELLOW
    _BOLD = colorama.Style.BRIGHT
    _RESET = colorama.Style.RESET_ALL
except ImportError:
    _CYAN = _MAGENTA = _YELLOW = _BOLD = _RESET = ""

CAT_BANNER = r"""
 /\_/\
( #.# )
 > ^ <
"""

TITLE = "H E L L O    C A T"
SUBTITLE = "Made By @.Trunith"
TAGLINE = "  Meow-ssive recon, zero manual effort.\n"


def print_banner():
    print(f"{_MAGENTA}{CAT_BANNER}{_RESET}")
    print(f"{_BOLD}{_CYAN}{TITLE}{_RESET}")
    print(f"{_CYAN}{SUBTITLE}{_RESET}\n")
    print(f"{_YELLOW}{TAGLINE}{_RESET}")

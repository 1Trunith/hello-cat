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

CAT_LINES = [
    " /\\_/\\ ",
    "( #.# )",
    " > ^ < ",
]

TITLE = "HELLO CAT"
SUBTITLE = "Made By @.Trunith"
TAGLINE = "Meow-ssive recon, zero manual effort."


def print_banner():
    print()
    print(f"{_MAGENTA}{CAT_LINES[0]}{_RESET}  {_BOLD}{_CYAN}{TITLE}{_RESET}")
    print(f"{_MAGENTA}{CAT_LINES[1]}{_RESET}  {_CYAN}{SUBTITLE}{_RESET}")
    print(f"{_MAGENTA}{CAT_LINES[2]}{_RESET}")
    print(f"\n{_YELLOW}{TAGLINE}{_RESET}\n")

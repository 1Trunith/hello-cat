import shutil
import sys
import threading

try:
    import colorama
    colorama.init(autoreset=False)
    _MAGENTA = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
    _RESET = colorama.Style.RESET_ALL
except ImportError:
    _MAGENTA = _RESET = ""

BAR_WIDTH = 30


def _terminal_width(default=100):
    try:
        return shutil.get_terminal_size((default, 20)).columns
    except OSError:
        return default


class ProgressBar:
    def __init__(self, total=None, label=""):
        self.total = total
        self.label = label
        self.current = 0
        self._lock = threading.Lock()
        self._finished = False

    def set_label(self, label):
        with self._lock:
            self.label = label

    def update(self, current=None, label=None):
        with self._lock:
            if current is not None:
                self.current = current
            else:
                self.current += 1
            if label is not None:
                self.label = label
            self._render()

    def _render(self):
        if self._finished:
            return
        max_width = _terminal_width()
        if self.total:
            pct = min(1.0, self.current / self.total) if self.total else 0
            filled = int(BAR_WIDTH * pct)
            bar = "#" * filled + "-" * (BAR_WIDTH - filled)
            line = f"\r{_MAGENTA}[{bar}] {pct * 100:5.1f}%  {self.label} ({self.current}/{self.total}){_RESET}"
        else:
            line = f"\r{_MAGENTA}[working] {self.current} done  {self.label}{_RESET}"
        line = line[:max_width - 1].ljust(max_width - 1)
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self, final_label=None):
        with self._lock:
            if final_label is not None:
                self.label = final_label
            if self.total:
                self.current = self.total
            self._render()
            self._finished = True
            sys.stdout.write("\n")
            sys.stdout.flush()

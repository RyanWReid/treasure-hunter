"""
TUI -- Terminal User Interface rendering engine

Zero-dependency terminal rendering with truecolor ANSI, box drawing,
gradient text, animated spinners, progress bars, tables, and panels.
Works on Windows 10+ (cmd, PowerShell, Windows Terminal) and Unix.

Everything here is pure Python stdlib -- no curses, no rich, no blessed.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
from dataclasses import dataclass

# ============================================================
# Terminal initialization
# ============================================================

def init_terminal() -> None:
    """Enable ANSI escape codes on Windows. Call once at startup."""
    if os.name == 'nt':
        os.system('')  # triggers cmd.exe ANSI init
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            for handle_id in (-11, -12):  # stdout, stderr
                handle = k32.GetStdHandle(handle_id)
                mode = ctypes.c_ulong()
                k32.GetConsoleMode(handle, ctypes.byref(mode))
                mode.value |= 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                k32.SetConsoleMode(handle, mode)
        except Exception:
            pass
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass


def get_terminal_size() -> tuple[int, int]:
    """Return (columns, rows)."""
    size = shutil.get_terminal_size((80, 24))
    return size.columns, size.lines


# ============================================================
# Color palette -- Red Team Dark with pirate gold accents
# ============================================================

@dataclass
class Palette:
    """Color theme for the TUI."""
    bg:       tuple[int, int, int] = (15, 15, 15)
    fg:       tuple[int, int, int] = (204, 204, 204)
    primary:  tuple[int, int, int] = (255, 50, 50)      # red
    secondary: tuple[int, int, int] = (255, 120, 0)     # orange
    accent:   tuple[int, int, int] = (255, 200, 0)      # gold
    info:     tuple[int, int, int] = (80, 180, 255)     # blue
    success:  tuple[int, int, int] = (50, 205, 50)      # green
    dim:      tuple[int, int, int] = (100, 100, 100)    # gray
    critical: tuple[int, int, int] = (255, 0, 0)        # bright red
    high:     tuple[int, int, int] = (255, 120, 0)      # orange
    medium:   tuple[int, int, int] = (255, 200, 0)      # yellow
    low:      tuple[int, int, int] = (80, 180, 255)     # blue

THEME = Palette()

# ============================================================
# ANSI helpers
# ============================================================

RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
ITALIC = '\033[3m'
UNDERLINE = '\033[4m'
REVERSE = '\033[7m'
HIDE_CURSOR = '\033[?25l'
SHOW_CURSOR = '\033[?25h'
CLEAR_SCREEN = '\033[2J\033[H'
CLEAR_LINE = '\033[2K'
ALT_SCREEN_ON = '\033[?1049h'
ALT_SCREEN_OFF = '\033[?1049l'


def fg(r: int, g: int, b: int) -> str:
    return f'\033[38;2;{r};{g};{b}m'


def bg_color(r: int, g: int, b: int) -> str:
    return f'\033[48;2;{r};{g};{b}m'


def move(row: int, col: int) -> str:
    return f'\033[{row};{col}H'


def color(text: str, rgb: tuple[int, int, int]) -> str:
    return f'{fg(*rgb)}{text}{RESET}'


def bold(text: str, rgb: tuple[int, int, int] | None = None) -> str:
    if rgb:
        return f'{BOLD}{fg(*rgb)}{text}{RESET}'
    return f'{BOLD}{text}{RESET}'


def dim_text(text: str) -> str:
    return color(text, THEME.dim)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape codes for length calculation."""
    return re.sub(r'\033\[[0-9;]*m', '', text)


def visible_len(text: str) -> int:
    return len(strip_ansi(text))


# ============================================================
# Gradient text
# ============================================================

def gradient(text: str, start: tuple[int, int, int], end: tuple[int, int, int]) -> str:
    """Apply smooth RGB gradient across text."""
    result = []
    n = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        t = i / n
        r = int(start[0] + (end[0] - start[0]) * t)
        g = int(start[1] + (end[1] - start[1]) * t)
        b = int(start[2] + (end[2] - start[2]) * t)
        result.append(f'\033[38;2;{r};{g};{b}m{ch}')
    result.append(RESET)
    return ''.join(result)


def gradient_multi(text: str, colors: list[tuple[int, int, int]]) -> str:
    """Multi-stop gradient."""
    result = []
    n = len(text)
    segments = len(colors) - 1
    for i, ch in enumerate(text):
        pos = i / max(n - 1, 1) * segments
        idx = min(int(pos), segments - 1)
        t = pos - idx
        c1, c2 = colors[idx], colors[idx + 1]
        r = int(c1[0] + (c2[0] - c1[0]) * t)
        g = int(c1[1] + (c2[1] - c1[1]) * t)
        b = int(c1[2] + (c2[2] - c1[2]) * t)
        result.append(f'\033[38;2;{r};{g};{b}m{ch}')
    result.append(RESET)
    return ''.join(result)


# ============================================================
# Box drawing
# ============================================================

BOX_ROUND = {
    'tl': '\u256d', 'tr': '\u256e', 'bl': '\u2570', 'br': '\u256f',
    'h': '\u2500', 'v': '\u2502',
    'lt': '\u251c', 'rt': '\u2524', 'tt': '\u252c', 'bt': '\u2534', 'x': '\u253c',
}

BOX_HEAVY = {
    'tl': '\u250f', 'tr': '\u2513', 'bl': '\u2517', 'br': '\u251b',
    'h': '\u2501', 'v': '\u2503',
    'lt': '\u2523', 'rt': '\u252b', 'tt': '\u2533', 'bt': '\u253b', 'x': '\u254b',
}

BOX_DOUBLE = {
    'tl': '\u2554', 'tr': '\u2557', 'bl': '\u255a', 'br': '\u255d',
    'h': '\u2550', 'v': '\u2551',
    'lt': '\u2560', 'rt': '\u2563', 'tt': '\u2566', 'bt': '\u2569', 'x': '\u256c',
}


def panel(content: str | list[str], title: str = '', width: int | None = None,
          box: dict | None = None, border_color: tuple[int, int, int] | None = None,
          title_color: tuple[int, int, int] | None = None) -> str:
    """Render a bordered panel with optional colored title."""
    if box is None:
        box = BOX_ROUND
    if border_color is None:
        border_color = THEME.dim
    if title_color is None:
        title_color = THEME.accent
    if width is None:
        width = min(get_terminal_size()[0], 70)

    tl, tr, bl, br = box['tl'], box['tr'], box['bl'], box['br']
    h, v = box['h'], box['v']
    inner = width - 2
    bc = fg(*border_color)

    lines = []

    # Top border
    if title:
        t = f' {color(title, title_color)} '
        t_vis = visible_len(t)
        left_pad = 2
        right_pad = inner - left_pad - t_vis
        lines.append(f'{bc}{tl}{h * left_pad}{RESET}{t}{bc}{h * max(0, right_pad)}{tr}{RESET}')
    else:
        lines.append(f'{bc}{tl}{h * inner}{tr}{RESET}')

    # Content
    if isinstance(content, str):
        content = content.split('\n')
    for line in content:
        pad = inner - 2 - visible_len(line)
        lines.append(f'{bc}{v}{RESET} {line}{" " * max(0, pad)} {bc}{v}{RESET}')

    # Bottom
    lines.append(f'{bc}{tl}{h * inner}{br}{RESET}')

    return '\n'.join(lines)


# ============================================================
# Severity badge
# ============================================================

def severity_badge(level: str) -> str:
    """Colored severity badge: [!!] CRITICAL, [!] HIGH, etc."""
    styles = {
        'critical': ('[!!]', THEME.critical),
        'high':     ('[!]',  THEME.high),
        'medium':   ('[*]',  THEME.medium),
        'low':      ('[-]',  THEME.low),
        'info':     ('[i]',  THEME.info),
    }
    tag, rgb = styles.get(level.lower(), ('[?]', THEME.dim))
    return bold(tag, rgb)


# ============================================================
# Table rendering
# ============================================================

def table(headers: list[str], rows: list[list[str]], max_width: int | None = None,
          max_col: int = 40, header_color: tuple[int, int, int] | None = None) -> str:
    """Render an aligned table with box-drawing borders."""
    if header_color is None:
        header_color = THEME.accent
    if max_width is None:
        max_width = get_terminal_size()[0] - 2

    b = BOX_ROUND
    ncols = len(headers)

    # Calculate column widths
    widths = [min(visible_len(h), max_col) for h in headers]
    for row in rows:
        for i, cell in enumerate(row[:ncols]):
            widths[i] = max(widths[i], min(visible_len(str(cell)), max_col))

    # Shrink if too wide
    total = sum(w + 3 for w in widths) + 1
    if total > max_width and widths:
        ratio = max_width / total
        widths = [max(4, int(w * ratio)) for w in widths]

    bc = fg(*THEME.dim)

    def hline(l, m, r):
        return f'{bc}{l}{"".join(b["h"] * (w + 2) + (m if i < ncols - 1 else "") for i, w in enumerate(widths))}{r}{RESET}'

    def dataline(cells, is_header=False):
        parts = []
        for i, cell in enumerate(cells[:ncols]):
            s = str(cell)
            vis = visible_len(s)
            w = widths[i]
            if vis > w:
                s = strip_ansi(s)[:w - 1] + '\u2026'
                vis = w
            pad = w - vis
            if is_header:
                s = bold(strip_ansi(s), header_color)
            parts.append(f' {s}{" " * pad} ')
        return f'{bc}{b["v"]}{RESET}' + f'{bc}{b["v"]}{RESET}'.join(parts) + f'{bc}{b["v"]}{RESET}'

    lines = [hline(b['tl'], b['tt'], b['tr'])]
    lines.append(dataline(headers, is_header=True))
    lines.append(hline(b['lt'], b['x'], b['rt']))
    for row in rows:
        lines.append(dataline(row))
    lines.append(hline(b['bl'], b['bt'], b['br']))

    return '\n'.join(lines)


# ============================================================
# Progress bar
# ============================================================

_HBLOCKS = ' \u258f\u258e\u258d\u258c\u258b\u258a\u2589\u2588'


def progress_bar(current: int, total: int, width: int = 30,
                 label: str = '', show_pct: bool = True,
                 bar_color: tuple[int, int, int] | None = None) -> str:
    """Smooth progress bar with sub-character resolution."""
    if bar_color is None:
        bar_color = THEME.success
    if total <= 0:
        total = 1

    pct = current / total
    filled_exact = width * pct
    filled_full = int(filled_exact)
    frac = filled_exact - filled_full

    bar = fg(*bar_color)
    bar += '\u2588' * filled_full
    if filled_full < width:
        bar += _HBLOCKS[int(frac * 8)]
    bar += fg(*THEME.dim)
    bar += '\u2591' * max(0, width - filled_full - 1)
    bar += RESET

    pct_str = f' {pct * 100:5.1f}%' if show_pct else ''
    return f'{label}[{bar}]{pct_str}'


# ============================================================
# Spinner
# ============================================================

SPINNER_FRAMES = {
    'braille': list('\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f'),
    'dots':    list('\u2801\u2802\u2804\u2840\u2880\u2820\u2810\u2808'),
    'pipe':    list('\u2524\u2518\u2534\u2514\u251c\u250c\u252c\u2510'),
    'line':    list('-\\|/'),
}


class Spinner:
    """Animated spinner running in a background thread."""

    def __init__(self, message: str = '', style: str = 'braille',
                 spin_color: tuple[int, int, int] | None = None):
        self.message = message
        self.frames = SPINNER_FRAMES.get(style, SPINNER_FRAMES['braille'])
        self.color = spin_color or THEME.accent
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _spin(self) -> None:
        i = 0
        c = fg(*self.color)
        sys.stdout.write(HIDE_CURSOR)
        while not self._stop.is_set():
            frame = self.frames[i % len(self.frames)]
            sys.stdout.write(f'\r{c}{frame}{RESET} {self.message}\033[K')
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.08)
        sys.stdout.write(f'\r\033[K{SHOW_CURSOR}')
        sys.stdout.flush()

    def start(self) -> Spinner:
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()

    def __enter__(self) -> Spinner:
        return self.start()

    def __exit__(self, *args) -> None:
        self.stop()


# ============================================================
# Input helpers
# ============================================================

def getch() -> str:
    """Read a single keypress. Returns the character or special key name."""
    if os.name == 'nt':
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ('\x00', '\xe0'):
            scan = msvcrt.getwch()
            _MAP = {'H': 'up', 'P': 'down', 'K': 'left', 'M': 'right',
                    'G': 'home', 'O': 'end', 'I': 'pgup', 'Q': 'pgdn'}
            return _MAP.get(scan, f'scan:{scan}')
        return ch
    else:
        import tty
        import termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 1)
            if ch == b'\x1b':
                import select
                # Wait longer for the rest of the escape sequence
                if select.select([sys.stdin], [], [], 0.15)[0]:
                    seq = os.read(fd, 5).decode('utf-8', errors='ignore')
                    _MAP = {'[A': 'up', '[B': 'down', '[C': 'right', '[D': 'left',
                            '[H': 'home', '[F': 'end', '[5~': 'pgup', '[6~': 'pgdn'}
                    return _MAP.get(seq, f'esc:{seq}')
                return 'esc'
            return ch.decode('utf-8', errors='ignore')
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def prompt(text: str, prompt_color: tuple[int, int, int] | None = None) -> str:
    """Colored input prompt."""
    if prompt_color is None:
        prompt_color = THEME.accent
    return input(f'{fg(*prompt_color)}{text}{RESET}')


def menu_select(options: list[str], title: str = '', selected: int = 0) -> int:
    """Interactive single-select menu with arrow key navigation.
    Returns the selected index, or -1 if escaped."""
    sys.stdout.write(HIDE_CURSOR)
    try:
        while True:
            # Draw
            sys.stdout.write(f'\r\033[K')
            if title:
                print(f'\n  {bold(title, THEME.accent)}')
            for i, opt in enumerate(options):
                if i == selected:
                    marker = color('\u25b6 ', THEME.primary)  # filled triangle
                    text = bold(opt, THEME.fg)
                else:
                    marker = dim_text('  ')
                    text = dim_text(opt)
                print(f'\r\033[K  {marker}{text}')

            key = getch()
            if key == 'up' and selected > 0:
                selected -= 1
            elif key == 'down' and selected < len(options) - 1:
                selected += 1
            elif key in ('\r', '\n'):
                return selected
            elif key == 'q':
                return -1
            # Number keys for direct selection (1-9)
            elif key.isdigit() and 1 <= int(key) <= len(options):
                return int(key) - 1

            # Move cursor back up to redraw
            sys.stdout.write(f'\033[{len(options) + (2 if title else 1)}A')
    finally:
        sys.stdout.write(SHOW_CURSOR)


# ============================================================
# Banner
# ============================================================

BANNER = r"""
  _____                                       _  _             _
 |_   _| _ _  ___  __ _  ___ _  _  _ _  ___  | || | _  _  _ _ | |_  ___  _ _
   | |  | '_|/ -_)/ _` |(_-<| || || '_|/ -_) | __ || || || ' \|  _|/ -_)| '_|
   |_|  |_|  \___|\__,_|/__/ \_,_||_|  \___| |_||_| \_,_||_||_|\__|\___||_|
"""


def render_banner() -> str:
    """Render the banner with a red-orange-gold gradient."""
    lines = BANNER.strip('\n').split('\n')
    rendered = []
    colors = [(255, 50, 50), (255, 120, 0), (255, 200, 0)]
    for i, line in enumerate(lines):
        t = i / max(len(lines) - 1, 1)
        r = int(colors[0][0] + (colors[-1][0] - colors[0][0]) * t)
        g = int(colors[0][1] + (colors[-1][1] - colors[0][1]) * t)
        b = int(colors[0][2] + (colors[-1][2] - colors[0][2]) * t)
        rendered.append(color(line, (r, g, b)))
    rendered.append('')
    rendered.append(f'  {dim_text("v2.1")}  {gradient("Captain" + chr(39) + "s Deck", (255, 200, 0), (255, 120, 0))}  {dim_text(chr(9875))}')
    return '\n'.join(rendered)


# ============================================================
# Screen management
# ============================================================

def clear() -> None:
    sys.stdout.write(CLEAR_SCREEN)
    sys.stdout.flush()


def enter_fullscreen() -> None:
    sys.stdout.write(ALT_SCREEN_ON + HIDE_CURSOR)
    sys.stdout.flush()


def exit_fullscreen() -> None:
    sys.stdout.write(SHOW_CURSOR + ALT_SCREEN_OFF)
    sys.stdout.flush()

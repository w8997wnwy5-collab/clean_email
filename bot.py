#!/usr/bin/env python3
"""Avvia il bot di pulizia della posta iCloud.

    python3 bot.py            apre il menu
    python3 bot.py --help     elenca i comandi
"""

import sys

if sys.version_info < (3, 10):
    sys.exit("Serve Python 3.10 o più recente.")

from clean_email.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

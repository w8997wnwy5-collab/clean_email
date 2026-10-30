"""Small helpers for talking with the user in the terminal."""

from __future__ import annotations

import getpass
import sys

YES = {"s", "si", "sì", "y", "yes", "ok"}
NO = {"n", "no"}


class Abort(Exception):
    """The user closed the input (Ctrl-D) or asked to stop."""


def say(text: str = "") -> None:
    print(text, flush=True)


def progress(text: str) -> None:
    """Status lines go to stderr, so that output such as JSON stays clean."""
    print(text, file=sys.stderr, flush=True)


def ask(prompt: str, default: str = "") -> str:
    try:
        answer = input(prompt).strip()
    except EOFError:
        raise Abort() from None
    return answer or default


def ask_secret(prompt: str) -> str:
    try:
        return getpass.getpass(prompt)
    except EOFError:
        raise Abort() from None


def confirm(prompt: str, default: bool = False) -> bool:
    hint = "[S/n]" if default else "[s/N]"
    while True:
        answer = ask(f"{prompt} {hint} ").lower()
        if not answer:
            return default
        if answer in YES:
            return True
        if answer in NO:
            return False
        say("Rispondi sì o no.")


def ask_int(prompt: str, default: int, low: int, high: int) -> int:
    while True:
        answer = ask(f"{prompt} [{default}]: ", str(default))
        if answer.isdigit() and low <= int(answer) <= high:
            return int(answer)
        say(f"Scrivi un numero da {low} a {high}.")


def pick_numbers(prompt: str, count: int) -> list[int]:
    """Read choices like «1 3 5-7», «tutte», or nothing; returns numbers from 1."""
    while True:
        answer = ask(prompt).lower().replace(",", " ")
        if answer in ("", "0", "nessuna", "nessuno"):
            return []
        if answer in ("tutte", "tutti", "t"):
            return list(range(1, count + 1))
        numbers: set[int] = set()
        valid = True
        for token in answer.split():
            first, dash, last = token.partition("-")
            if dash and first.isdigit() and last.isdigit() and 1 <= int(first) <= int(last) <= count:
                numbers.update(range(int(first), int(last) + 1))
            elif not dash and token.isdigit() and 1 <= int(token) <= count:
                numbers.add(int(token))
            else:
                valid = False
        if valid:
            return sorted(numbers)
        say(f"Scrivi numeri da 1 a {count}, per esempio «1 3» o «2-4».")


def pick_one(prompt: str, options: list[str]) -> int:
    """Show numbered options and return the index (from 0) of the chosen one."""
    for n, option in enumerate(options, 1):
        say(f"  {n}) {option}")
    while True:
        answer = ask(prompt)
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return int(answer) - 1
        say(f"Scrivi un numero da 1 a {len(options)}.")

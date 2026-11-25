"""Terminal prompts for the guided setup. Kept small so tests can stand in for it."""

from __future__ import annotations

import getpass
import sys
import textwrap


class Console:
    width = 78

    def say(self, text: str = "") -> None:
        for paragraph in text.split("\n"):
            print(self._wrap(paragraph) if paragraph.strip() else paragraph)
        sys.stdout.flush()

    def _wrap(self, paragraph: str) -> str:
        indent = paragraph[: len(paragraph) - len(paragraph.lstrip())]
        return textwrap.fill(
            paragraph.strip(),
            self.width,
            initial_indent=indent,
            subsequent_indent=indent,
            break_long_words=False,  # paths and commands stay in one piece
            break_on_hyphens=False,
        )

    def step(self, number: int, total: int, title: str) -> None:
        print(f"\n[{number}/{total}] {title}\n" + "-" * self.width)

    def ok(self, text: str) -> None:
        print(f"  ✓ {text}")
        sys.stdout.flush()

    def warn(self, text: str) -> None:
        self.say(f"  ! {text}")

    def ask(self, prompt: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default else ""
        while True:
            answer = input(f"{prompt}{suffix}: ").strip()
            if answer or default is not None:
                return answer or (default or "")

    def confirm(self, prompt: str, default: bool = True) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            answer = input(f"{prompt} [{hint}]: ").strip().lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False

    def choose(self, prompt: str, options: list[str], default: int = 0) -> int:
        """Index of the chosen option."""
        for index, option in enumerate(options, 1):
            first, *rest = option.split("\n")
            print(f"  {index}. {first}")
            for line in rest:
                print(textwrap.fill(line, self.width, initial_indent="     ", subsequent_indent="     "))
        while True:
            answer = input(f"{prompt} [{default + 1}]: ").strip()
            if not answer:
                return default
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return int(answer) - 1

    def secret(self, prompt: str) -> str:
        return getpass.getpass(f"{prompt}: ")

    def wait(self, prompt: str) -> None:
        input(f"{prompt} — then press Enter ")

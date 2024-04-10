import os
import re
from functools import cached_property
from pathlib import Path
from typing import Annotated

from decocli import Namespace, cli

_PROCFS = Path("/proc")
_PID_REGEX = re.compile("^[0-9]+$")
_PPID_REGEX = re.compile(r"PPid:[ \t]*([0-9]+)")


class Args(Namespace):
    pattern: Annotated[str, "-p"]
    truncate: Annotated[int, "-t"] = 0


class Process:
    pid: int
    ppid: int
    children: list
    name: str
    cmdline: str
    matches: bool

    def __init__(self, pid: int, args: Args):
        self.pid = pid
        self.children: list[Process] = []

        pdir = _PROCFS / str(pid)

        self.ppid = int(_PPID_REGEX.search((pdir / "status").read_text()).group(1))

        cmdline = [a.decode() for a in (pdir / "cmdline").read_bytes().split(b"\0")]
        self.name = cmdline.pop(0)
        if any(" " in a for a in cmdline):
            self.cmdline = str(cmdline)
        else:
            self.cmdline = " ".join(cmdline)

        if args.truncate > 0:
            self.cmdline = self.cmdline[: args.truncate]

        self.matches = any(args.pattern in a for a in [self.name, *cmdline])

    def print_matching(self, indent="", always_match=False):
        if not (self.matches or self.children_match or always_match):
            return

        print(f"{indent}[{self.pid}] {self.name} {self.cmdline}")
        for p in self.children:
            p.print_matching(indent + "  ", self.matches or always_match)

    @cached_property
    def children_match(self) -> bool:
        for c in self.children:
            if c.matches or c.children_match:
                return True

        return False


def list_processes(args: Args) -> list[Process]:
    processes_by_pid: dict[int, Process] = {}
    self_pid = os.getpid()

    for entry in _PROCFS.iterdir():
        if not _PID_REGEX.match(entry.name):
            continue

        pid = int(entry.name)
        if pid == self_pid:
            continue

        processes_by_pid[pid] = Process(pid, args)

    processes = []
    for process in list(processes_by_pid.values()):
        if ppid := process.ppid:
            processes_by_pid[ppid].children.append(process)
        else:
            processes.append(process)

    return processes


@cli
def main(args: Args):
    for p in list_processes(args):
        p.print_matching()

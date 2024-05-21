import os
import re
from functools import cached_property
from pathlib import Path
from typing import Annotated

from annocli import Namespace, cli

_PROCFS = Path("/proc")
_PID_REGEX = re.compile("^[0-9]+$")
_PPID_REGEX = re.compile(r"PPid:[ \t]*([0-9]+)")
_NAME_REGEX = re.compile(r"Name:[ \t]*([^ \t].+)")


class Args(Namespace):
    pattern: Annotated[str, "pattern"]
    threads: Annotated[bool, "-T"]
    truncate: Annotated[int, "-t"] = 0


class Thread:
    def __init__(self, tid: int, name: str):
        self.tid = tid
        self.name = name


class Process:
    pid: int
    ppid: int
    children: list
    name: str
    cmdline: str
    matches: bool
    threads: list[Thread] | None

    def __init__(self, pid: int, args: Args):
        self.pid = pid
        self.children: list[Process] = []

        pdir = _PROCFS / str(pid)

        self.ppid = int(_PPID_REGEX.search((pdir / "status").read_text()).group(1))

        cmdline_raw = (pdir / "cmdline").read_bytes()

        if cmdline_raw:
            cmdline = [a.decode() for a in cmdline_raw.split(b"\0")]
            self.name = cmdline.pop(0)
            cmdline.pop(-1)

            if any(" " in a for a in cmdline):
                self.cmdline = str(cmdline)
            else:
                self.cmdline = " ".join(cmdline)

            if args.truncate > 0:
                self.cmdline = self.cmdline[: args.truncate]
            self.matches = any(args.pattern in a for a in [self.name, *cmdline])
        else:
            self.name = ""
            self.cmdline = []
            self.matches = False

        if args.threads:
            self.threads = []
            for e in (pdir / "task").iterdir():
                tid = int(e.name)
                if tid == pid:
                    continue
                if m := _NAME_REGEX.search((e / "status").read_text()):
                    self.threads.append(Thread(tid, m.group(1)))
        else:
            self.threads = None

    def print_matching(self, indent="", always_match=False):
        if not (self.matches or self.children_match or always_match):
            return

        print(f"{indent}[{self.pid}] {self.name} {self.cmdline}")

        if self.threads:
            for t in self.threads:
                print(f"{indent}  [{t.tid}]{{{t.name}}}")

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

        try:
            processes_by_pid[pid] = Process(pid, args)
        except FileNotFoundError:
            pass

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

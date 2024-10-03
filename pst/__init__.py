import os
import re
from functools import cached_property
from pathlib import Path

from annocli import Arg, Namespace, entrypoint

_PROCFS = Path("/proc")

_PGRP_REGEXP = re.compile(r".*\) [a-zA-Z] [0-9]+ ([0-9]+)")


class Args(Namespace):
    pattern: str = Arg(positional=True)
    threads: bool = Arg("-T")
    truncate: int = Arg("-t", default=0)
    show_cwd: bool = Arg("-w")
    show_uid: bool = Arg("-u")
    show_gid: bool = Arg("-g")
    show_basic_fds: bool = Arg("-F")
    show_process_groups: bool = Arg("-G")


@entrypoint
def main(args: Args):
    for p in list_processes(args):
        p.print_matching()


class Thread:
    def __init__(self, tid: int, name: str):
        self.tid = tid
        self.name = name


class Process:
    pid: int
    children: list
    _args: Args

    def __init__(self, pid: int, args: Args):
        self.pid = pid
        self.children: list[Process] = []
        self._args = args

    @cached_property
    def pdir(self) -> Path:
        return _PROCFS / str(self.pid)

    @cached_property
    def ppid(self) -> int | None:
        if (ppid := self.attrs.get("PPid")) is None:
            return None

        return int(ppid)

    @cached_property
    def cmdline_args(self) -> list[str]:
        if not (raw := (self.pdir / "cmdline").read_bytes()):
            return []

        return [a.decode() for a in raw.split(b"\0")][:-1]

    @cached_property
    def cmdline(self) -> str:
        if not (args := self.cmdline_args[1:]):
            return ""

        if any(" " in a for a in args):
            cmdline = str(args)
        else:
            cmdline = " ".join(args)

        return cmdline

    @cached_property
    def name(self) -> str:
        if self.cmdline_args:
            return self.cmdline_args[0]

        try:
            return f'*{self.attrs.get("Name")}*' or ""
        except FileNotFoundError:
            return ""

    @cached_property
    def pgroup(self) -> str:
        try:
            if self._args.show_process_groups and (m := _PGRP_REGEXP.search((self.pdir / "stat").read_text())):
                return m.group(1)
        except FileExistsError:
            pass

        return ""

    @cached_property
    def matches(self) -> bool:
        return any(self._args.pattern in a for a in (str(self.pid), *self.cmdline_args))

    @cached_property
    def threads(self) -> list[Thread]:
        if not self._args.threads:
            return []

        threads = []
        for tdir in (self.pdir / "task").iterdir():
            tid = int(tdir.name)
            if tid == self.pid:
                continue
            try:
                threads.append(Thread(tid, self.read_attrs(tdir).get("Name") or ""))
            except FileNotFoundError:
                pass

        return threads

    @cached_property
    def attrs(self) -> dict[str, str]:
        return self.read_attrs()

    @cached_property
    def cwd(self) -> str | None:
        if not self._args.show_cwd:
            return None

        try:
            return (self.pdir / "cwd").readlink()
        except (PermissionError, FileNotFoundError) as e:
            return f"!{e}"

    @cached_property
    def uid(self) -> str:
        if not self._args.show_uid:
            return ""

        return self.normalize_guids(self.attrs["Uid"])

    @cached_property
    def gid(self) -> str:
        if not self._args.show_gid:
            return ""

        return self.normalize_guids(self.attrs["Gid"])

    @cached_property
    def fd_lines(self) -> list[str]:
        if not self._args.show_basic_fds:
            return []

        lines = []
        for fd in (0, 1, 2):
            try:
                fd_path = (self.pdir / "fd" / str(fd)).readlink()
            except (PermissionError, FileNotFoundError) as e:
                fd_path = f"!{e}"
            lines.append(f"{fd} -> {fd_path}")

        return lines

    @staticmethod
    def normalize_guids(raw: str) -> str:
        guids = raw.split()
        if len(set(guids)) == 1:
            return guids[0]

        return f"r:{guids[0]} e:{guids[1]} ss:{guids[2]} fs:{guids[3]}"

    def repr(self, indent: str):
        if cwd := (self.cwd or ""):
            cwd = f" ({cwd})"

        guids = self.uid
        if gid := self.gid:
            guids += f" : {gid}"
        if guids:
            guids = f"[{guids}]"

        process_ids = str(self.pid)
        if self.pgroup:
            process_ids += f";{self.pgroup}"

        proc_str = f"[{process_ids}]{guids}{cwd} {self.name} {self.cmdline}"

        if self._args.truncate > 0:
            proc_str = proc_str[: self._args.truncate]

        for fd_line in self.fd_lines:
            proc_str += f"\n{indent}    {fd_line}"

        return f"{indent}{proc_str}"

    @cached_property
    def children_match(self) -> bool:
        for c in self.children:
            if c.matches or c.children_match:
                return True

        return False

    def print_matching(self, indent="", always_match=False):
        try:
            if not (self.matches or self.children_match or always_match):
                return

            print(self.repr(indent))
            for t in self.threads:
                print(f"{indent}  [{t.tid}]{{{t.name}}}")

            for p in self.children:
                p.print_matching(indent + "  ", self.matches or always_match)
        except FileNotFoundError:
            pass

    def read_attrs(self, pdir: Path | None = None) -> dict[str, str]:
        attrs = {}
        for line in ((pdir or self.pdir) / "status").read_text().splitlines():
            attr, val = line.split(":", 1)
            val = val.lstrip(" \t")
            attrs[attr] = val

        return attrs


def list_processes(args: Args) -> list[Process]:
    processes_by_pid: dict[int, Process] = {}
    self_pid = os.getpid()

    for entry in _PROCFS.iterdir():
        try:
            pid = int(entry.name)
        except ValueError:
            continue

        if pid == self_pid:
            continue

        processes_by_pid[pid] = Process(pid, args)

    processes = []
    for process in processes_by_pid.values():
        try:
            if ppid := process.ppid:
                processes_by_pid[ppid].children.append(process)
            else:
                processes.append(process)
        except FileNotFoundError:
            pass

    for process in processes_by_pid.values():
        process.children.sort(key=lambda c: len(c.children) + len(c.threads))

    return processes

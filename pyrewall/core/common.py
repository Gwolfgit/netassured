# Common functions
import subprocess
from collections import deque

import jc


def jc_exec(program: str, commands: list[str]):
    cmd_output = subprocess.check_output(commands, text=True)
    return jc.parse(program, cmd_output)


def do_exec(commands: list[str]):
    return subprocess.check_output(commands, text=True)


def round_robin(Queue: deque):
    item = Queue.popleft()
    Queue.append(item)
    return item

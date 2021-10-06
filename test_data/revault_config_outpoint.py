#!/usr/bin/env python3
"""
Return an outpoint set in the config as to be revaulted.
"""

import json
import sys


def read_all_stdin():
    buf = ""
    while len(buf) == 0 or buf[-1] != "\n":
        buf += sys.stdin.read()
    return buf


if __name__ == "__main__":
    request = json.loads(read_all_stdin())
    resp = {"revault": [request["config"]["outpoint_to_revault"]]}
    sys.stdout.write(json.dumps(resp))
    sys.stdout.flush()

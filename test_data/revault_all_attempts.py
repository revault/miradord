#!/usr/bin/env python3
"""
Return all the new attempts we get from the watchtower as to be revaulted.
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
    all_attempts = [
        info["deposit_outpoint"] for info in request["block_info"]["new_attempts"]
    ]
    resp = {"revault": all_attempts}
    sys.stdout.write(json.dumps(resp))
    sys.stdout.flush()

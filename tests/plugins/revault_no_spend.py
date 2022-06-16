#!/usr/bin/env python3
"""A plugin which returns any attempt without candidate spend transaction as needing to be revaulted"""

import json
import sys


def read_request():
    """Read a JSON request from stdin up to the '\n' delimiter."""
    buf = ""
    while len(buf) == 0 or buf[-1] != "\n":
        buf += sys.stdin.read()
    return json.loads(buf)


if __name__ == "__main__":
    req = read_request()
    block_info = req["block_info"]

    vaults_without_spend_outpoints = []
    for vault in block_info["new_attempts"]:
        if vault["candidate_tx"] is None:
            vaults_without_spend_outpoints.append(vault["deposit_outpoint"])

    resp = {"revault": vaults_without_spend_outpoints}
    sys.stdout.write(json.dumps(resp))
    sys.stdout.flush()

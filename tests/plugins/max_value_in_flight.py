#!/usr/bin/env python3
"""A plugin which enforces a maximum total value in flight (being unvaulted).

It needs as part of its config:
    - A "data_dir" entry specifying where it is going to store its 'database'.
    - A "max_value" entry specifying the maximum value in flight to enforce.

It stores the in flight vaults info as "deposit outpoint", "value" pairs in a
JSON file at the root of its data directory.
"""

import json
import os
import sys


DATASTORE_FNAME = "datastore.json"
JSON_KEY = "in_flight"


def read_request():
    """Read a JSON request from stdin up to the '\n' delimiter."""
    buf = ""
    while len(buf) == 0 or buf[-1] != "\n":
        buf += sys.stdin.read()
    return json.loads(buf)


def update_in_flight(config, entries):
    data_store = os.path.join(config["data_dir"], DATASTORE_FNAME)
    with open(data_store, "w+") as f:
        f.write(json.dumps({JSON_KEY: entries}))


def maybe_create_data_dir(config):
    if not os.path.isdir(config["data_dir"]):
        assert not os.path.exists(config["data_dir"])
        os.makedirs(config["data_dir"])
        update_in_flight(config, {})


def recorded_attempts(config):
    """Read the current value in-flight from a text file in our datadir."""
    maybe_create_data_dir(config)
    with open(os.path.join(config["data_dir"], DATASTORE_FNAME), "r") as f:
        data_store = json.loads(f.read())
    return data_store[JSON_KEY]


if __name__ == "__main__":
    req = read_request()
    config = req["config"]
    assert "data_dir" in config and "max_value" in config
    maybe_create_data_dir(config)
    assert DATASTORE_FNAME in os.listdir(config["data_dir"])

    resp = {}
    if req["method"] == "new_block":
        block_info = req["block_info"]
        # First update the recorded attempts with the new and pass attempts.
        in_flight = recorded_attempts(config)
        for op in block_info["successful_attempts"] + block_info["revaulted_attempts"]:
            del in_flight[op]
        for v in block_info["new_attempts"]:
            in_flight[v["deposit_outpoint"]] = v["value"]
        update_in_flight(config, in_flight)

        # Did we get above the threshold? Note we might stay a bit above the threshold
        # for the time that the vaults we told the WT to revault previously actually get
        # their Cancel transaction confirmed.
        resp = {"revault": []}
        value_in_flight = sum([in_flight[k] for k in in_flight])
        while value_in_flight > config["max_value"] and len(block_info["new_attempts"]) > 0:
            v = block_info["new_attempts"].pop(0)
            resp["revault"].append(v["deposit_outpoint"])
            value_in_flight -= v["value"]
            continue
    elif req["method"] == "invalidate_block":
        # We don't really care
        pass
    else:
        # TODO: maybe we should reply saying that we don't know what
        # they're talking about?
        pass

    sys.stdout.write(json.dumps(resp))
    sys.stdout.flush()

"""
Lot of the code here is stolen from C-lightning's test suite. This is surely
Rusty Russell or Christian Decker who wrote most of this (I'd put some sats on
cdecker), so credits to them ! (MIT licensed)
"""
import itertools
import json
import logging
import os
import re
import subprocess
import threading
import time

from nacl.public import PrivateKey as Curve25519Private

TIMEOUT = int(os.getenv("TIMEOUT", 60))
EXECUTOR_WORKERS = int(os.getenv("EXECUTOR_WORKERS", 20))
VERBOSE = os.getenv("VERBOSE", "0") == "1"
LOG_LEVEL = os.getenv("LOG_LEVEL", "trace")
assert LOG_LEVEL in ["trace", "debug", "info", "warn", "error"]
BITCOIND_PATH = os.getenv("BITCOIND_PATH", "bitcoind")

COIN = 10 ** 8

CSV = 72

# FIXME: This is a hack until we have a python-revault-tx. We use static xprivs
# and a static deposit address across all tests
STKS_XPRIVS = [
    "xprv9s21ZrQH143K3dHHJFdvqxsuDmR6uVmidU3ByetiTpc1Tyw9LD92iZBUiCCGBTqPULEjAZPPkZmhT7sxiSo47moNnELA1aZzDG6AQquzSdY",
    "xprvA12WBRLLa6eYs8DucMdv2nYusFAwLxYvNbN54ixQmfRojyLG3NbZxCTAdgNfmhBoPKkNUXAxJK6nc2gd6NjJmZWihYQf5mPKn719kmtSPJj",
    "xprvA1xrc2Pp7KkTneNq32UctAG5dHk4T2CAq6fmJeVQesXDi3HPUr361fSarv3VnBFHW14u9gm57eC7sdEM7muL8oc8uV3ctmUa4ZR3FTgM5Wp",
    "xprvA12Gy5MjHkiswfVT1gPpsTFai1zSJbQ8bcDTQygfUf77VzvCtdQBa3X3CufPhTUYUaYCECdKyjjZz7Du6a9ckRh1BC7V8haub6F2kYMCct6",
]
STKS_XPUBS = [
    "xpub661MyMwAqRbcG7MkQHAwD6pdmoFbJxVZzgxnn3JL2A8zLnGHskTHGMVxZUch5T2PHyQwxGtc2BTnw9swJUiXfKbzFggryY8AEwkc1amoCbm",
    "xpub6E1ravsEQUCr5cJNiPAvPvVeRH1RkRGmjpHfs7N2KzxncmfQauupVzmeUxzZ4osSfJc2SC9fMcn1aAPEc1b89nhdvVjeLtQgCQHdnJ4ND42",
    "xpub6ExD1XvhwhJm18TJ941dFJCpBKaYrUv2CKbN72u2DD4CaqcY2PMLZTm4iBvV8LMnNDnxjsC8Pk7chXMEw9ejesmZNX4dJsW7vbDBcASxNX7",
    "xpub6E1dNatd88HBA9Zv7hvqEbCKG3pvi47yxq94DN6H2ze6NoFMSAiS7qqX4CUfDHrt6UsEHah8UPp1Bw2q9p2pcZHNvQxMiaoeErGUTKBmj4P",
]
MANS_XPRIVS = [
    "xprv9wHokC2KXdTSszgTSY5gv5UfS94Bc9AdyL1BB5aYN8utyoUTFhUZw5JwojEDAG8RDQwCRMhUoymeGKj2wM7CsSZEj1ucbXpojQcWt8kEvKa",
    "xprv9xBSDGRCEcijj5maNFNamzcjkF6uwt7KFKdnGGktxfN4zE3atv8jbX7pdLuR1b4NRhJtUyNVA2niGAofXenAhpXrDyaSdBA6gm6wJvWPVTi",
]
MANS_XPUBS = [
    "xpub6AHA9hZDN11k6UkvYZchHDRPzAtg1btVLYvmyTz9vUSsrboboEnpUsdRezyNomhRwNicTud2wRGe1FJjCtMK5zZ1TDANE8Mm2BYkjdTVhmR",
    "xpub6BAncmx64zH2wZr3UGub98ZUJGwQMLqAcYZP4fAWWzu3s2NjSTSz9KSJUcYKudaDavLjRgsVrMVBKvDRERbrFyjcv5Esk3uVFgeWjhMXKAs",
]
# FIXME: make cosigs fucking opt-in :sob:
COSIG_PRIVKEYS = [
    "3369df522f601c8f81f5e69f68c991399dcc067b3ef9324abe749d3e32cfd1da",
    "340e40c25ec68e7b7d13d703cd04a472f60307aeca724790159ae4a6948a35e7",
    "a02ef51da78e20fd4f56a0350faac9747cc19e7d57f24679858ffd846c6a77a7",
    "e51a21fa2d6d3e1d0808d0b820b1973d973f8f01b0514d76329dd7865fb82752",
]
COSIG_PUBKEYS = [
    "02f844e875157e07c9d7f2cd7af622bd8db17b2587eb4360596705f4d9f052b0e6",
    "025f1ef18b26f353fb662617a4e2bc67d188e21687a893f3fff9ee8a33b490a1ba",
    "02906bb8b9ef1b6d5f3497069856c74916afb156dab8c6e36362d048f8ecfca08a",
    "02d84768bc18dd85b1897788885259bd85c913d94783920fdd8f748269ea802010",
]
DERIV_INDEX = 7651
DEPOSIT_ADDRESS = "bcrt1qgprmrfkz5mucga0ec046v0sf8yg2y4za99c0h26ew5ycfx64sgdsl0u2j3"


class NoiseKeypair:
    """A pair of Curve25519 keys"""

    def __init__(
        self,
        privkey,
    ):
        self.privkey = privkey
        self.pubkey = bytes(
            Curve25519Private(privkey).public_key
        )


def wait_for(success, timeout=TIMEOUT, debug_fn=None):
    """
    Run success() either until it returns True, or until the timeout is reached.
    debug_fn is logged at each call to success, it can be useful for debugging
    when tests fail.
    """
    start_time = time.time()
    interval = 0.25
    while not success() and time.time() < start_time + timeout:
        if debug_fn is not None:
            logging.info(debug_fn())
        time.sleep(interval)
        interval *= 2
        if interval > 5:
            interval = 5
    if time.time() > start_time + timeout:
        raise ValueError("Error waiting for {}", success)


# FIXME: have a python-revault-tx lib to avoid this hack..
def get_descriptors(stks_xpubs, cosigs_keys, mans_xpubs, mans_thresh, cpfp_xpubs, csv):
    # tests/test_framework/../../contrib/tools/mscompiler/target/debug/mscompiler
    mscompiler_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "contrib",
            "tools",
            "mscompiler",
        )
    )
    mscompiler_cargo_toml = os.path.join(mscompiler_dir, "Cargo.toml")
    try:
        subprocess.check_call(
            ["cargo", "build", "--manifest-path", mscompiler_cargo_toml]
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"Error compiling mscompiler: {str(e)}")
        raise e

    mscompiler_bin = os.path.join(mscompiler_dir, "target", "debug", "mscompiler")
    cmd = [
        mscompiler_bin,
        f"{json.dumps(stks_xpubs)}",
        f"{json.dumps(cosigs_keys)}",
        f"{json.dumps(mans_xpubs)}",
        str(mans_thresh),
        f"{json.dumps(cpfp_xpubs)}",
        str(csv),
    ]
    try:
        descs_json = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running mscompiler with command '{' '.join(cmd)}'")
        raise e

    descs = json.loads(descs_json)
    return (
        descs["deposit_descriptor"],
        descs["unvault_descriptor"],
        descs["cpfp_descriptor"],
    )


def compile_rust_binary(directory_path):
    cargo_toml = os.path.join(directory_path, "Cargo.toml")
    try:
        subprocess.check_call(
            ["cargo", "build", "--manifest-path", cargo_toml]
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"Error compiling {str(directory_path)}: {str(e)}")
        raise e


# FIXME: have a python-revault-tx lib to avoid this hack..
def get_signed_txs(
    stks_xprivs,
    mans_xprivs,
    cosig_privkeys,
    deposit_desc,
    unvault_desc,
    cpfp_desc,
    emer_addr,
    deposit_outpoint,
    deposit_value,
    deriv_index,
):
    """
    Get the Unvault, Cancel, Emergency and Unvault Emergency fully signed
    transactions extracted, ready to be broadcast.
    """
    # tests/test_framework/../../contrib/tools/txbuilder/target/debug/txbuilder
    txbuilder_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "contrib",
            "tools",
            "txbuilder",
        )
    )
    compile_rust_binary(txbuilder_dir)

    txbuilder_bin = os.path.join(txbuilder_dir, "target", "debug", "txbuilder")
    cmd = [
        txbuilder_bin,
        f"{json.dumps(stks_xprivs)}",
        f"{json.dumps(mans_xprivs)}",
        f"{json.dumps(cosig_privkeys)}",
        f"{str(deposit_desc)}",
        f"{str(unvault_desc)}",
        f"{str(cpfp_desc)}",
        emer_addr,
        deposit_outpoint,
        str(int(deposit_value)),
        str(deriv_index),
    ]
    try:
        txs_json = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running txbuilder with command '{' '.join(cmd)}'")
        raise e

    return json.loads(txs_json)


class TailableProc(object):
    """A monitorable process that we can start, stop and tail.

    This is the base class for the daemons. It allows us to directly
    tail the processes and react to their output.
    """

    def __init__(self, outputDir=None, verbose=True):
        self.logs = []
        self.logs_cond = threading.Condition(threading.RLock())
        self.env = os.environ.copy()
        self.running = False
        self.proc = None
        self.outputDir = outputDir
        self.logsearch_start = 0

        # Set by inherited classes
        self.cmd_line = []
        self.prefix = ""

        # Should we be logging lines we read from stdout?
        self.verbose = verbose

        # A filter function that'll tell us whether to filter out the line (not
        # pass it to the log matcher and not print it to stdout).
        self.log_filter = lambda _: False

    def start(self, stdin=None, stdout=None, stderr=None):
        """Start the underlying process and start monitoring it."""
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        self.proc = subprocess.Popen(
            self.cmd_line,
            stdin=stdin,
            stdout=stdout if stdout else subprocess.PIPE,
            stderr=stderr if stderr else subprocess.PIPE,
            env=self.env,
        )
        self.thread = threading.Thread(target=self.tail)
        self.thread.daemon = True
        self.thread.start()
        self.running = True

    def save_log(self):
        if self.outputDir:
            logpath = os.path.join(self.outputDir, "log")
            with open(logpath, "w") as f:
                for l in self.logs:
                    f.write(l + "\n")

    def stop(self, timeout=10):
        self.save_log()
        self.proc.terminate()

        # Now give it some time to react to the signal
        rc = self.proc.wait(timeout)

        if rc is None:
            self.proc.kill()
            self.proc.wait()

        self.thread.join()

        return self.proc.returncode

    def kill(self):
        """Kill process without giving it warning."""
        self.proc.kill()
        self.proc.wait()
        self.thread.join()

    def tail(self):
        """Tail the stdout of the process and remember it.

        Stores the lines of output produced by the process in
        self.logs and signals that a new line was read so that it can
        be picked up by consumers.
        """
        out = self.proc.stdout.readline
        err = self.proc.stderr.readline
        for line in itertools.chain(iter(out, ""), iter(err, "")):
            if len(line) == 0:
                break
            if self.log_filter(line.decode("utf-8")):
                continue
            if self.verbose:
                logging.debug(f"{self.prefix}: {line.decode().rstrip()}")
            with self.logs_cond:
                self.logs.append(str(line.rstrip()))
                self.logs_cond.notifyAll()
        self.running = False
        self.proc.stdout.close()
        self.proc.stderr.close()

    def is_in_log(self, regex, start=0):
        """Look for `regex` in the logs."""

        ex = re.compile(regex)
        for l in self.logs[start:]:
            if ex.search(l):
                logging.debug("Found '%s' in logs", regex)
                return l

        logging.debug(f"{self.prefix} : Did not find {regex} in logs")
        return None

    def wait_for_logs(self, regexs, timeout=TIMEOUT):
        """Look for `regexs` in the logs.

        We tail the stdout of the process and look for each regex in `regexs`,
        starting from last of the previous waited-for log entries (if any).  We
        fail if the timeout is exceeded or if the underlying process
        exits before all the `regexs` were found.

        If timeout is None, no time-out is applied.
        """
        logging.debug("Waiting for {} in the logs".format(regexs))

        exs = [re.compile(r) for r in regexs]
        start_time = time.time()
        pos = self.logsearch_start

        while True:
            if timeout is not None and time.time() > start_time + timeout:
                print("Time-out: can't find {} in logs".format(exs))
                for r in exs:
                    if self.is_in_log(r):
                        print("({} was previously in logs!)".format(r))
                raise TimeoutError('Unable to find "{}" in logs.'.format(exs))

            with self.logs_cond:
                if pos >= len(self.logs):
                    if not self.running:
                        raise ValueError("Process died while waiting for logs")
                    self.logs_cond.wait(1)
                    continue

                for r in exs.copy():
                    self.logsearch_start = pos + 1
                    if r.search(self.logs[pos]):
                        logging.debug("Found '%s' in logs", r)
                        exs.remove(r)
                        break
                if len(exs) == 0:
                    return self.logs[pos]
                pos += 1

    def wait_for_log(self, regex, timeout=TIMEOUT):
        """Look for `regex` in the logs.

        Convenience wrapper for the common case of only seeking a single entry.
        """
        return self.wait_for_logs([regex], timeout)

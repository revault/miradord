import logging
import os

from decimal import Decimal
from ephemeral_port_reserve import reserve
from test_framework.authproxy import AuthServiceProxy
from test_framework.utils import TailableProc, wait_for, COIN, TIMEOUT, BITCOIND_PATH


class BitcoinDProxy:
    def __init__(self, data_dir, network, rpc_port):
        self.cookie_path = os.path.join(data_dir, network, ".cookie")
        self.rpc_port = rpc_port
        self.wallet_name = "miradord-tests"

    def __getattr__(self, name):
        assert not (name.startswith("__") and name.endswith("__")), "Python internals"

        with open(self.cookie_path) as fd:
            authpair = fd.read()
        service_url = (
            f"http://{authpair}@localhost:{self.rpc_port}/wallet/{self.wallet_name}"
        )
        proxy = AuthServiceProxy(service_url, name)

        def f(*args):
            return proxy.__call__(*args)

        # Make debuggers show <function bitcoin.rpc.name> rather than <function
        # bitcoin.rpc.<lambda>>
        f.__name__ = name
        return f


class Bitcoind(TailableProc):
    def __init__(self, bitcoin_dir, rpcport=None):
        TailableProc.__init__(self, bitcoin_dir, verbose=False)

        if rpcport is None:
            rpcport = reserve()

        self.bitcoin_dir = bitcoin_dir
        self.rpcport = rpcport
        self.p2pport = reserve()
        self.prefix = "bitcoind"

        regtestdir = os.path.join(bitcoin_dir, "regtest")
        if not os.path.exists(regtestdir):
            os.makedirs(regtestdir)

        self.cmd_line = [
            BITCOIND_PATH,
            "-datadir={}".format(bitcoin_dir),
            "-printtoconsole",
            "-server",
            "-logtimestamps",
            "-rpcthreads=16",
        ]
        bitcoind_conf = {
            "port": self.p2pport,
            "rpcport": rpcport,
            "debug": 1,
            "fallbackfee": Decimal(1000) / COIN,
        }
        self.conf_file = os.path.join(bitcoin_dir, "bitcoin.conf")
        with open(self.conf_file, "w") as f:
            f.write("chain=regtest\n")
            f.write("[regtest]\n")
            for k, v in bitcoind_conf.items():
                f.write(f"{k}={v}\n")

        self.rpc = BitcoinDProxy(bitcoin_dir, "regtest", rpcport)

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Done loading", timeout=TIMEOUT)

        logging.info("BitcoinD started")

    def stop(self):
        self.rpc.stop()
        return TailableProc.stop(self)

    # wait_for_mempool can be used to wait for the mempool before generating
    # blocks:
    # True := wait for at least 1 transation
    # int > 0 := wait for at least N transactions
    # 'tx_id' := wait for one transaction id given as a string
    # ['tx_id1', 'tx_id2'] := wait until all of the specified transaction IDs
    def generate_block(self, numblocks=1, wait_for_mempool=0):
        if wait_for_mempool:
            if isinstance(wait_for_mempool, str):
                wait_for_mempool = [wait_for_mempool]
            if isinstance(wait_for_mempool, list):
                wait_for(
                    lambda: all(
                        txid in self.rpc.getrawmempool() for txid in wait_for_mempool
                    )
                )
            else:
                wait_for(lambda: len(self.rpc.getrawmempool()) >= wait_for_mempool)

        old_blockcount = self.rpc.getblockcount()
        addr = self.rpc.getnewaddress()
        self.rpc.generatetoaddress(numblocks, addr)
        wait_for(lambda: self.rpc.getblockcount() == old_blockcount + numblocks)

    def create_utxo(self, address, amount):
        """Send {amount} coins to this {address}, return the outpoint of the
        created UTXO."""
        txid = self.rpc.sendtoaddress(address, amount)
        vout = 0
        while True:
            txoinfo = self.rpc.gettxout(txid, vout)
            if txoinfo["scriptPubKey"]["address"] == address:
                return txid, f"{txid}:{vout}"
            vout += 1

    def generate_tx_with_feerate(self, feerate):
        """Send 1 coin to an address"""
        addr = self.rpc.getnewaddress()
        amount = 1
        comment = ""
        comment_to = ""
        subtract_fee_amount = False
        replaceable = False
        conf_target = None
        est_mode = "unset"
        avoid_reuse = False
        fee_rate = feerate
        txid = self.rpc.sendtoaddress(
            addr,
            amount,
            comment,
            comment_to,
            subtract_fee_amount,
            replaceable,
            conf_target,
            est_mode,
            avoid_reuse,
            feerate,
        )
        return txid

    def get_block_stats(self, block_height):
        return self.rpc.getblockstats(block_height)

    def get_coins(self, amount_btc):
        # subsidy halving is every 150 blocks on regtest, it's a rough estimate
        # to avoid looping in most cases
        numblocks = amount_btc // 25 + 1
        while self.rpc.getbalance() < amount_btc:
            self.generate_block(numblocks)

    def generate_blocks_censor(self, n, txids):
        """Generate {n} blocks ignoring {txids}"""
        fee_delta = COIN
        for txid in txids:
            self.rpc.prioritisetransaction(txid, None, -fee_delta)
        self.generate_block(n)
        for txid in txids:
            self.rpc.prioritisetransaction(txid, None, fee_delta)

    def estimatesmartfee(self, conf_target):
        return self.rpc.estimatesmartfee(conf_target)

    def simple_reorg(self, height, shift=0):
        """
        Reorganize chain by creating a fork at height={height} and:
            - If shift >=0:
                - re-mine all mempool transactions into {height} + shift
                  (with shift floored at 1)
            - Else:
                - don't re-mine the mempool transactions

        Note that tx's that become invalid at {height} (because coin maturity,
        locktime etc.) are removed from mempool. The length of the new chain
        will be original + 1 OR original + {shift}, whichever is larger.

        For example: to push tx's backward from height h1 to h2 < h1,
        use {height}=h2.

        Or to change the txindex of tx's at height h1:
        1. A block at height h2 < h1 should contain a non-coinbase tx that can
            be pulled forward to h1.
        2. Set {height}=h2 and {shift}= h1-h2
        """
        orig_len = self.rpc.getblockcount()
        old_hash = self.rpc.getblockhash(height)
        if height + shift > orig_len:
            final_len = height + shift
        else:
            final_len = 1 + orig_len

        self.rpc.invalidateblock(old_hash)
        self.wait_for_log(
            r"InvalidChainFound: invalid block=.*  height={}".format(height)
        )
        memp = self.rpc.getrawmempool()

        if shift < 0:
            self.generate_blocks_censor(1 + final_len - height, memp)
        elif shift == 0:
            self.generate_block(1 + final_len - height, memp)
        else:
            self.generate_blocks_censor(shift, memp)
            self.generate_block(1 + final_len - (height + shift), memp)
        self.wait_for_log(r"UpdateTip: new best=.* height={}".format(final_len))

    def startup(self):
        try:
            self.start()
        except Exception:
            self.stop()
            raise

        info = self.rpc.getnetworkinfo()

        if info["version"] < 210000:
            self.rpc.stop()
            raise ValueError(
                "bitcoind is too old. At least version 21000"
                " (v0.21.0) is needed, current version is {}".format(info["version"])
            )

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()
        self.proc.wait()

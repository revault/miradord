import os
import tempfile
import time

from fixtures import *
from test_framework.utils import COIN, DEPOSIT_ADDRESS, DERIV_INDEX, CSV


def test_max_value_in_flight(miradord, bitcoind):
    """
    Sanity check that we are only going to revault when there is more value in flight
    than we configure the plugin to authorize.
    """
    plugin_path = os.path.join(
        os.path.dirname(__file__), "plugins", "max_value_in_flight.py"
    )
    datadir = os.path.join(
        tempfile.mkdtemp(prefix="max_value_plugin-", dir="/tmp"), "datadir"
    )
    max_value = 12 * COIN
    deposit_value = 4
    miradord.add_plugins(
        [{"path": plugin_path, "config": {"data_dir": datadir, "max_value": max_value}}]
    )

    # Should get us exactly to the max value
    unvault_txids = []
    for _ in range(3):
        deposit_txid, deposit_outpoint = bitcoind.create_utxo(
            DEPOSIT_ADDRESS, deposit_value
        )
        bitcoind.generate_block(1, deposit_txid)
        txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
        unvault_txids.append(bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"])
        bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
        bitcoind.generate_block(1, unvault_txids[-1])
        miradord.wait_for_log(
            f"Got a confirmed Unvault UTXO at '{unvault_txids[-1]}:0'",
        )
    time.sleep(3)
    # The Cancel transactions have not been broadcast
    assert len(bitcoind.rpc.getrawmempool()) == 0
    for txid in unvault_txids:
        assert bitcoind.rpc.gettxout(txid, 0, True) is not None

    # One more will get us above the threshold
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)
    cancel_txid = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"])["txid"]
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO at '{unvault_txid}:0'",
            f"Broadcasted Cancel transaction '{txs['cancel']['tx']}'",
            f"Unvault transaction '{unvault_txid}' for vault at '{deposit_outpoint}' is still unspent",
        ]
    )
    bitcoind.generate_block(1, wait_for_mempool=cancel_txid)
    miradord.wait_for_log(
        f"Cancel transaction was confirmed for vault at '{deposit_outpoint}'"
    )


def test_multiple_plugins(miradord, bitcoind):
    """Test we use the union of all plugins output to revault. That is, the stricter one
    will always rule."""
    # Start with the max value plugin
    plugin_path = os.path.join(
        os.path.dirname(__file__), "plugins", "max_value_in_flight.py"
    )
    datadir = os.path.join(
        tempfile.mkdtemp(prefix="max_value_plugin-", dir="/tmp"), "datadir"
    )
    max_value = 3 * COIN
    deposit_value = 1
    miradord.add_plugins(
        [{"path": plugin_path, "config": {"data_dir": datadir, "max_value": max_value}}]
    )

    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)
    miradord.wait_for_log(
        f"Got a confirmed Unvault UTXO at '{unvault_txid}:0'",
    )
    # The Cancel transaction has not been broadcast
    assert "bestblock" in bitcoind.rpc.gettxout(unvault_txid, 0, True)

    # Now add the "revault everything plugin"
    plugin_path = os.path.join(os.path.dirname(__file__), "plugins", "revault_all.py")
    miradord.add_plugins([{"path": plugin_path}])
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )

    # 1 more unvault (1BTC) should not get us above the threshold but the second plugins
    # will tell us to revault no matter what.
    bitcoind.generate_block(1, deposit_txid)
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)
    cancel_txid = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"])["txid"]
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO at '{unvault_txid}:0'",
            f"Broadcasted Cancel transaction '{txs['cancel']['tx']}'",
            f"Unvault transaction '{unvault_txid}' for vault at '{deposit_outpoint}' is still unspent",
        ]
    )
    bitcoind.generate_block(1, wait_for_mempool=cancel_txid)
    miradord.wait_for_log(
        f"Cancel transaction was confirmed for vault at '{deposit_outpoint}'"
    )

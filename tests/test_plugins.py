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
    spend_txs = []
    for _ in range(3):
        deposit_txid, deposit_outpoint = bitcoind.create_utxo(
            DEPOSIT_ADDRESS, deposit_value
        )
        bitcoind.generate_block(1, deposit_txid)
        txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
        spend_txs.append(txs["spend"]["tx"])
        unvault_txids.append(
            bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
        )
        bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
        bitcoind.generate_block(1, unvault_txids[-1])
        miradord.wait_for_logs(
            [
                f"Got a confirmed Unvault UTXO at '{unvault_txids[-1]}:0'",
                "Done processing block",
            ]
        )
    # The Cancel transactions have not been broadcast
    assert len(bitcoind.rpc.getrawmempool()) == 0
    # If we mine a new block, they'll still won't be
    bitcoind.generate_block(1)
    miradord.wait_for_logs(
        [f"Unvault transaction '{txid}' .* is still unspent" for txid in unvault_txids]
        + ["Done processing block"]
    )
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

    # Now mine the spend txs to get back to 0 value in-flight
    bitcoind.generate_block(CSV)
    for spend_tx in spend_txs:
        bitcoind.rpc.sendrawtransaction(spend_tx)
    bitcoind.generate_block(1, wait_for_mempool=len(spend_txs))
    # We must be able to spend
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)
    miradord.wait_for_logs(
        [f"Got a confirmed Unvault UTXO at '{unvault_txid}:0'", "Done processing block"]
    )
    assert bitcoind.rpc.gettxout(unvault_txid, 0, True) is not None
    # Leave it a chance to broadcast the Cancel
    bitcoind.generate_block(1)
    miradord.wait_for_logs(
        [
            f"Unvault transaction '{unvault_txid}' .* is still unspent",
            "Done processing block",
        ]
    )
    assert bitcoind.rpc.gettxout(unvault_txid, 0, True) is not None
    # We should be able to broadcast the Spend
    bitcoind.generate_block(CSV - 1)
    bitcoind.rpc.sendrawtransaction(txs["spend"]["tx"])
    bitcoind.generate_block(1, 1)
    miradord.wait_for_log(
        f"Noticed .* that Spend transaction was confirmed for vault at '{deposit_outpoint}'"
    )
    # Generate two days worth of blocks, the WT should forget about this vault
    bitcoind.generate_block(288)
    miradord.wait_for_log(f"Forgetting about consumed vault at '{deposit_outpoint}'")


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

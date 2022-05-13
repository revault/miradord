import os
import pytest

from fixtures import *
from test_framework.utils import COIN, DEPOSIT_ADDRESS, DERIV_INDEX, CSV


def test_simple_unvault_broadcast(miradord, bitcoind):
    """
    Sanity check we detect the broadcast of the Unvault transaction for a
    vault we registered.
    """
    deposit_value = 12
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)

    # Make the watchtower revault everything
    plugin_path = os.path.join(os.path.dirname(__file__), "plugins", "revault_all.py")
    miradord.add_plugins([{"path": plugin_path}])

    # Register this vault on the WT
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)

    # Broadcast the Unvault
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)

    cancel_txid = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"]["20"])["txid"]
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO for vault at '{deposit_outpoint}'",
            f"Broadcasted Cancel transaction '{txs['cancel']['tx']['20']}'",
            f"Unvault transaction '{unvault_txid}' for vault at '{deposit_outpoint}' is still unspent",
        ]
    )

    bitcoind.generate_block(1, wait_for_mempool=cancel_txid)
    miradord.wait_for_log(
        f"Cancel transaction was confirmed for vault at '{deposit_outpoint}'"
    )

    # Generate two days worth of blocks, the WT should
    bitcoind.generate_block(288)
    miradord.wait_for_log(f"Forgetting about consumed vault at '{deposit_outpoint}'")


def test_spent_cancel_detection(miradord, bitcoind):
    """
    Sanity check we detect a Cancel is confirmed even after it was spent.
    """
    deposit_value = 12
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)

    # Make the watchtower revault everything
    plugin_path = os.path.join(os.path.dirname(__file__), "plugins", "revault_all.py")
    miradord.add_plugins([{"path": plugin_path}])

    # Register this vault on the WT, and make it broadcast the Cancel
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)
    cancel_tx = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"]["20"])
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO for vault at '{deposit_outpoint}'",
            f"Broadcasted Cancel transaction '{txs['cancel']['tx']['20']}'",
            f"Unvault transaction '{unvault_txid}' for vault at '{deposit_outpoint}' is still unspent",
        ]
    )

    # Now, the unconfirmed Cancel is a new deposit: get the Unvault tx for this one and broadcast it
    txs = miradord.get_signed_txs(
        f"{cancel_tx['txid']}:0", cancel_tx["vout"][0]["value"] * COIN
    )
    unvault_txid = bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])

    bitcoind.generate_block(1, wait_for_mempool=[cancel_tx["txid"], unvault_txid])
    miradord.wait_for_log(
        f"Noticed at height .* that Cancel transaction was confirmed for vault at '{deposit_outpoint}'"
    )


def test_simple_spend_detection(miradord, bitcoind):
    """
    Sanity check we detect an Unvault spent by a Spend (ie not canceled).
    """
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)

    # Make the watchtower revault nothing
    plugin_path = os.path.join(
        os.path.dirname(__file__), "plugins", "revault_nothing.py"
    )
    miradord.add_plugins([{"path": plugin_path}])

    # Register this vault on the WT, make sure it does not broadcast the Cancel
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)
    miradord.wait_for_logs(
        [
            f"Unvault transaction '{unvault_txid}' .* is still unspent",
            "Done processing block",
        ]
    )

    # Broadcast and confirm the Spend
    bitcoind.generate_block(CSV)
    bitcoind.rpc.sendrawtransaction(txs["spend"]["tx"])
    bitcoind.generate_block(1, 1)
    miradord.wait_for_log(
        f"Noticed .* that Spend transaction was confirmed for vault at '{deposit_outpoint}'"
    )

    # Generate two days worth of blocks, the WT should forget about this vault
    bitcoind.generate_block(288)
    miradord.wait_for_log(f"Forgetting about consumed vault at '{deposit_outpoint}'")


def assert_cancel_broadcast(
    miradord, bitcoind, deposit_outpoint, deposit_value, feerate
):
    """Register a vault to be watched by the WT, Unvault it, and assert the Cancel transaction
    at the given feerate is broadcasted in response.
    """
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)

    cancel_tx = txs["cancel"]["tx"][f"{feerate}"]
    cancel_txid = bitcoind.rpc.decoderawtransaction(cancel_tx)["txid"]
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO for vault at '{deposit_outpoint}'",
            f"Broadcasted Cancel transaction '{cancel_tx}'",
            f"Unvault transaction '{unvault_txid}' for vault at '{deposit_outpoint}' is still unspent",
        ]
    )
    bitcoind.generate_block(1, wait_for_mempool=cancel_txid)
    miradord.wait_for_log(
        f"Cancel transaction was confirmed for vault at '{deposit_outpoint}'"
    )


@pytest.mark.mock_bitcoind
def test_cancel_feerate_adaptation(miradord, bitcoind):
    """
    Sanity check the poller will chose the Cancel tx presigned with the feerate adapted
    to the next block feerate estimate it got from bitcoind.
    """
    # Make the watchtower revault everything
    plugin_path = os.path.join(os.path.dirname(__file__), "plugins", "revault_all.py")
    miradord.add_plugins([{"path": plugin_path}])

    # Create a new deposit and Mock the estimate to return 10sat/vb. It should make the poller
    # broadcast the 20sat/vb Cancel.
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    bitcoind.proxy.mocks["estimatesmartfee"] = {"feerate": 10 * 10 ** 3 / COIN}
    assert_cancel_broadcast(miradord, bitcoind, deposit_outpoint, deposit_value, 20)

    # Create a new deposit and Mock the estimate to return 28sat/vb. It should make the poller
    # broadcast the 100sat/vb Cancel.
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    bitcoind.proxy.mocks["estimatesmartfee"] = {"feerate": 28 * 10 ** 3 / COIN}
    assert_cancel_broadcast(miradord, bitcoind, deposit_outpoint, deposit_value, 100)

    # Create a new deposit and Mock the estimate to return 180sat/vb. It should make the poller
    # broadcast the 200sat/vb Cancel.
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    bitcoind.proxy.mocks["estimatesmartfee"] = {"feerate": 180 * 10 ** 3 / COIN}
    assert_cancel_broadcast(miradord, bitcoind, deposit_outpoint, deposit_value, 200)

    # Create a new deposit and Mock the estimate to return 350sat/vb. It should make the poller
    # broadcast the 500sat/vb Cancel.
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    bitcoind.proxy.mocks["estimatesmartfee"] = {"feerate": 350 * 10 ** 3 / COIN}
    assert_cancel_broadcast(miradord, bitcoind, deposit_outpoint, deposit_value, 500)

    # Create a new deposit and Mock the estimate to return 700sat/vb. It should make the poller
    # broadcast the 1000sat/vb Cancel.
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    bitcoind.proxy.mocks["estimatesmartfee"] = {"feerate": 700 * 10 ** 3 / COIN}
    assert_cancel_broadcast(miradord, bitcoind, deposit_outpoint, deposit_value, 1_000)

    # Create a new deposit and Mock the estimate to return 1700sat/vb. It should make the poller
    # still broadcast the 1000sat/vb Cancel, as we make the (security) assumption the feerate
    # won't go above 1_000 sat/vb for the entire duration of the timelock.
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(1, deposit_txid)
    bitcoind.proxy.mocks["estimatesmartfee"] = {"feerate": 1_700 * 10 ** 3 / COIN}
    assert_cancel_broadcast(miradord, bitcoind, deposit_outpoint, deposit_value, 1_000)

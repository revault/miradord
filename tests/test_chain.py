import os
from random import randint
from math import ceil

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

    cancel_txid = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"])["txid"]
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO for vault at '{deposit_outpoint}'",
            f"Broadcasted Cancel transaction '{txs['cancel']['tx']}'",
            f"Unvault transaction '{unvault_txid}' for vault at '{deposit_outpoint}' is"
            " still unspent",
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
    cancel_tx = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"])
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO for vault at '{deposit_outpoint}'",
            f"Broadcasted Cancel transaction '{txs['cancel']['tx']}'",
            f"Unvault transaction '{unvault_txid}' for vault at '{deposit_outpoint}' is"
            " still unspent",
        ]
    )

    # Now, the unconfirmed Cancel is a new deposit: get the Unvault tx for this one and broadcast it
    txs = miradord.get_signed_txs(
        f"{cancel_tx['txid']}:0", cancel_tx["vout"][0]["value"] * COIN
    )
    unvault_txid = bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])

    bitcoind.generate_block(1, wait_for_mempool=[cancel_tx["txid"], unvault_txid])
    miradord.wait_for_log(
        "Noticed at height .* that Cancel transaction was confirmed for vault at"
        f" '{deposit_outpoint}'"
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
        "Noticed .* that Spend transaction was confirmed for vault at"
        f" '{deposit_outpoint}'"
    )

    # Generate two days worth of blocks, the WT should forget about this vault
    bitcoind.generate_block(288)
    miradord.wait_for_log(f"Forgetting about consumed vault at '{deposit_outpoint}'")


def test_vault_reserve_feerate_update(miradord, bitcoind):
    """
    Check that the vault_reserve_feerate is updated as expected with each new block.
    """
    START_BLOCK = 120
    WINDOW_LEN = 144 * 90
    HIGH_FEERATE = 2000
    # Starting at block 120, with no transactions in the next block the vault_reserve_feerate
    # should not increase.
    bitcoind.generate_block(1, [])
    miradord.wait_for_logs([f"Not enough blocks to compute vault reserve feerate"])
    miradord.wait_for_logs(
        [f"last_update for vault reserve feerate set to {START_BLOCK+1}"]
    )

    # FIXME: generating so many blocks takes me ~25 minutes
    # for block in range(START_BLOCK+1, WINDOW_LEN+5):
    #     wait_for_mempool = []
    #     for tx in range(0, 10):
    #         txid = bitcoind.generate_tx_with_feerate(HIGH_FEERATE)
    #         wait_for_mempool.append(txid)
    #     bitcoind.generate_block(1, wait_for_mempool)

    # miradord.wait_for_logs[f"vault reserve feerate updated to"]


def test_feerate_estimation(miradord, bitcoind):
    """
    Test estimatesmartfee usage and fallback
    """
    # Generate some transaction history for estimatesmartfee.
    # 10 transactions in 25 blocks (send to deposit address)
    amount = 1
    for block in range(0, 25):
        wait_for_mempool = []
        for tx in range(0, randint(5, 15)):
            txid, outpoint = bitcoind.create_utxo(DEPOSIT_ADDRESS, amount)
            wait_for_mempool.append(txid)
        bitcoind.generate_block(1, wait_for_mempool)

    feerate = ceil(
        bitcoind.estimatesmartfee(1)["feerate"] * 100000
    )  # Convert from BTC/kb to sat/vB
    miradord.wait_for_logs([f"feerate estimate is {feerate}"])

    # FIXME: How to test fallback?

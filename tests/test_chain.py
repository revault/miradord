from bitcoin.core import COIN
from fixtures import *
from test_framework.utils import DEPOSIT_ADDRESS, DERIV_INDEX


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

    # Register this vault on the WT
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)

    # Broadcast the Unvault
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)

    cancel_txid = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"])["txid"]
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO at '{unvault_txid}:0'",
            f"Broadcasted Cancel transaction '{txs['cancel']['tx']}'",
            f"Cancel transaction '{cancel_txid}' for vault at '{deposit_outpoint}' is still unconfirmed",
        ]
    )

    bitcoind.generate_block(1, wait_for_mempool=cancel_txid)
    miradord.wait_for_log(
        f"Vault at '{deposit_outpoint}' Cancel transaction .* confirmed"
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

    # Register this vault on the WT, and make it broadcast the Spend
    txs = miradord.watch_vault(deposit_outpoint, deposit_value * COIN, DERIV_INDEX)
    unvault_txid = bitcoind.rpc.decoderawtransaction(txs["unvault"]["tx"])["txid"]
    bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])
    bitcoind.generate_block(1, unvault_txid)
    cancel_tx = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"])
    miradord.wait_for_logs(
        [
            f"Got a confirmed Unvault UTXO at '{unvault_txid}:0'",
            f"Broadcasted Cancel transaction '{txs['cancel']['tx']}'",
            f"Cancel transaction '{cancel_tx['txid']}' for vault at '{deposit_outpoint}' is still unconfirmed",
        ]
    )

    # Now, the unconfirmed Cancel is a new deposit: get the Unvault tx for this one and broadcast it
    txs = miradord.get_signed_txs(
        f"{cancel_tx['txid']}:0", cancel_tx["vout"][0]["value"] * COIN
    )
    unvault_txid = bitcoind.rpc.sendrawtransaction(txs["unvault"]["tx"])

    bitcoind.generate_block(1, wait_for_mempool=[cancel_tx["txid"], unvault_txid])
    miradord.wait_for_log(
        f"Noticed at height .* that Cancel transaction '{cancel_tx['txid']}' was confirmed for vault at '{deposit_outpoint}'"
    )

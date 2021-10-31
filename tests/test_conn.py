from fixtures import *
from test_framework.utils import COIN, DEPOSIT_ADDRESS, DERIV_INDEX


def test_simple_client_server(miradord, bitcoind):
    """
    Sanity check we can connect to the WT and register a vault to be watched for
    """
    # Sending for a non-existing outpoint they will NACK
    assert not miradord.send_sigs(
        {
            "030fac04165b606dea3b8f81ada5eb66ca181d5215c873fcf46623ea7cf8e98b1b": "304402205870a4bd7bca8147f3b8ca97e0f42166d223b5c1921c2843530e290a3712cd23022039dc778788b35caf0724028c2c9dec855118cc416dc4f2ed6213f0f6e3a681a6"
        },
        "9c05f3169986caf69cebf2ec82a027e7d3f77c37731de72849bd3d1c6abd0543",
        "150131e9c18da0c46bc5ed6e37f4f75bb077df68ace9da9a12f084ba7171c3d8:0",
        DERIV_INDEX,
    )

    # Now actually create a deposit
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(6, deposit_txid)

    # If we don't send any thing it won't ACK
    txs = miradord.get_signed_txs(deposit_outpoint, deposit_value * COIN)
    emer_txid = bitcoind.rpc.decoderawtransaction(txs["emer"]["tx"])["txid"]
    assert not miradord.send_sigs({}, emer_txid, deposit_outpoint, DERIV_INDEX)

    # We can send many messages through the same connection
    noise_conn = miradord.get_noise_conn()

    # Now if we send all the Emergency transaction it will ACK
    assert miradord.send_sigs(
        txs["emer"]["sigs"], emer_txid, deposit_outpoint, DERIV_INDEX, noise_conn
    )

    # And if we send the rest it'll start watching for this vault
    unemer_txid = bitcoind.rpc.decoderawtransaction(txs["unemer"]["tx"])["txid"]
    assert miradord.send_sigs(
        txs["unemer"]["sigs"], unemer_txid, deposit_outpoint, DERIV_INDEX, noise_conn
    )
    cancel_txid = bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"])["txid"]
    assert miradord.send_sigs(
        txs["cancel"]["sigs"], cancel_txid, deposit_outpoint, DERIV_INDEX, noise_conn
    )
    miradord.wait_for_log("Now watching for Unvault broadcast.")

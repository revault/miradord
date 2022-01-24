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
        {},
        {},
        "150131e9c18da0c46bc5ed6e37f4f75bb077df68ace9da9a12f084ba7171c3d8:0",
        DERIV_INDEX,
    )

    # Now actually create a deposit
    deposit_value = 0.5
    deposit_txid, deposit_outpoint = bitcoind.create_utxo(
        DEPOSIT_ADDRESS, deposit_value
    )
    bitcoind.generate_block(6, deposit_txid)

    # If we don't send anything it won't ACK
    assert not miradord.send_sigs({}, {}, {}, deposit_outpoint, DERIV_INDEX)

    # We can send many messages through the same connection
    noise_conn = miradord.get_noise_conn()

    # Now if we send all the revocation transactions' sigs it will ACK
    txs = miradord.get_signed_txs(deposit_outpoint, deposit_value * COIN)
    assert miradord.send_sigs(
        txs["emer"]["sigs"],
        txs["cancel"]["sigs"],
        txs["unemer"]["sigs"],
        deposit_outpoint,
        DERIV_INDEX,
        noise_conn,
    )
    miradord.wait_for_log(f"Registered a new vault at '{deposit_outpoint}'")

    # Ooops... I did it again!
    assert miradord.send_sigs(
        txs["emer"]["sigs"],
        txs["cancel"]["sigs"],
        txs["unemer"]["sigs"],
        deposit_outpoint,
        DERIV_INDEX,
        noise_conn,
    )
    miradord.wait_for_log(
        f"Got signatures for already registered vault '{deposit_outpoint}'"
    )

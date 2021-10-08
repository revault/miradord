import json
import logging
import os
import random
import socket
import toml

from test_framework.utils import (
    TailableProc,
    VERBOSE,
    LOG_LEVEL,
    get_signed_txs,
    STKS_XPRIVS,
    MANS_XPRIVS,
    COSIG_PRIVKEYS,
    DERIV_INDEX,
    TIMEOUT,
)
from nacl.public import PrivateKey as Curve25519Private
from noise.connection import NoiseConnection, Keypair


# FIXME: it's a bit clumsy. Miradord should stick to be the `miradord` process object
# and we should have another class (PartialRevaultNetwork?) to stuff helpers and all
# info not strictly necessary to running the process.
class Miradord(TailableProc):
    def __init__(
        self,
        datadir,
        deposit_desc,
        unvault_desc,
        cpfp_desc,
        emer_addr,
        listen_port,
        noise_priv,
        stk_noise_secret,
        coordinator_noise_key,
        coordinator_port,
        bitcoind,
        plugins=[],
    ):
        TailableProc.__init__(self, datadir, verbose=VERBOSE)

        self.prefix = os.path.split(datadir)[-1]
        self.stk_noise_secret = stk_noise_secret
        self.noise_secret = noise_priv
        self.listen_port = listen_port
        self.deposit_desc = deposit_desc
        self.unvault_desc = unvault_desc
        self.cpfp_desc = cpfp_desc
        self.emer_addr = emer_addr
        self.bitcoind = bitcoind

        # The data is stored in a per-network directory. We need to create it
        # in order to write the Noise private key
        self.datadir_with_network = os.path.join(datadir, "regtest")
        os.makedirs(self.datadir_with_network, exist_ok=True)

        bin = os.path.join(
            os.path.dirname(__file__), "..", "..", "target/debug/miradord"
        )
        self.conf_file = os.path.join(datadir, "config.toml")
        self.cmd_line = [bin, "--conf", f"{self.conf_file}"]

        self.noise_secret_file = os.path.join(self.datadir_with_network, "noise_secret")
        with open(self.noise_secret_file, "wb") as f:
            f.write(noise_priv)
        wt_noise_key = bytes(Curve25519Private(noise_priv).public_key)
        stk_noise_key = bytes(Curve25519Private(self.stk_noise_secret).public_key)
        logging.debug(
            f"Watchtower Noise key: {wt_noise_key.hex()}, Stakeholder Noise key: {stk_noise_key.hex()}"
        )

        bitcoind_cookie = os.path.join(bitcoind.bitcoin_dir, "regtest", ".cookie")
        with open(self.conf_file, "w") as f:
            f.write(f"data_dir = '{datadir}'\n")
            f.write("daemon = false\n")
            f.write(f"log_level = '{LOG_LEVEL}'\n")

            f.write(f'stakeholder_noise_key = "{stk_noise_key.hex()}"\n')

            f.write(f'coordinator_host = "127.0.0.1:{coordinator_port}"\n')
            f.write(f'coordinator_noise_key = "{coordinator_noise_key}"\n')
            f.write("coordinator_poll_seconds = 5\n")

            f.write(f'listen = "127.0.0.1:{listen_port}"\n')

            f.write("[scripts_config]\n")
            f.write(f'deposit_descriptor = "{deposit_desc}"\n')
            f.write(f'unvault_descriptor = "{unvault_desc}"\n')
            f.write(f'cpfp_descriptor = "{cpfp_desc}"\n')
            f.write(f'emergency_address = "{emer_addr}"\n')

            f.write("[bitcoind_config]\n")
            f.write('network = "regtest"\n')
            f.write(f"cookie_path = '{bitcoind_cookie}'\n")
            f.write(f"addr = '127.0.0.1:{bitcoind.rpcport}'\n")
            f.write("poll_interval_secs = 5\n")

            f.write(f"\n{toml.dumps({'plugins': plugins})}\n")

    def start(self):
        TailableProc.start(self)
        self.wait_for_logs(
            ["bitcoind now synced", "Listener thread started", "Started miradord."]
        )

    def stop(self, timeout=10):
        return TailableProc.stop(self)

    def cleanup(self):
        try:
            self.stop()
        except Exception:
            self.proc.kill()

    def add_plugins(self, plugins):
        """Takes a list of dict representing plugin config to add to the watchtower and
        restarts it."""
        self.stop()
        conf = toml.loads(open(self.conf_file, "r").read())
        if "plugins" not in conf:
            conf["plugins"] = []
        conf["plugins"] += plugins
        open(self.conf_file, "w").write(toml.dumps(conf))
        self.start()

    def get_signed_txs(self, deposit_outpoint, deposit_value, deriv_index=DERIV_INDEX):
        """
        Get the Unvault, Cancel, Emergency and Unvault Emergency (in this order) fully
        signed transactions extracted, ready to be broadcast for this deposit UTXO info.
        """
        return get_signed_txs(
            STKS_XPRIVS,
            MANS_XPRIVS,
            COSIG_PRIVKEYS,
            self.deposit_desc,
            self.unvault_desc,
            self.cpfp_desc,
            self.emer_addr,
            deposit_outpoint,
            deposit_value,
            deriv_index,
        )

    def get_noise_conn(self):
        """Create a new connection to the watchtower, performing the Noise handshake."""
        conn = NoiseConnection.from_name(b"Noise_KK_25519_ChaChaPoly_SHA256")

        conn.set_as_initiator()
        conn.set_keypair_from_private_bytes(Keypair.STATIC, self.stk_noise_secret)
        conn.set_keypair_from_private_bytes(Keypair.REMOTE_STATIC, self.noise_secret)
        conn.start_handshake()

        sock = socket.socket()
        sock.settimeout(TIMEOUT // 10)
        sock.connect(("localhost", self.listen_port))
        msg = conn.write_message(b"practical_revault_0")
        sock.sendall(msg)
        resp = sock.recv(32 + 16)  # Key size + Mac size
        assert len(resp) > 0
        conn.read_message(resp)

        return sock, conn

    def send_msg(self, name, params, noise_conn=None):
        """
        Send a message to the watchtower. If a Noise connection isn't provided
        a new one is established.
        """
        if noise_conn is None:
            (sock, conn) = self.get_noise_conn()
        else:
            (sock, conn) = noise_conn

        # Practical-revault specifies messages format as almost-JSONRPC
        msg_id = random.randint(0, 2 ** 32)
        msg = {"id": msg_id, "method": name, "params": params}
        msg_serialized = json.dumps(msg).encode("utf-8")
        logging.debug(f"Sending message {msg}")

        # We encrypt messages in two parts to length-prefix them
        prefix = (len(msg_serialized) + 16).to_bytes(2, "big")
        encrypted_header = conn.encrypt(prefix)
        encrypted_body = conn.encrypt(msg_serialized)
        sock.sendall(encrypted_header + encrypted_body)

        # Same for decryption, careful to read length first and then the body
        resp_header = sock.recv(2 + 16)
        assert len(resp_header) > 0
        resp_header = conn.decrypt(resp_header)
        resp_len = int.from_bytes(resp_header, "big")
        resp = sock.recv(resp_len)
        assert len(resp) == resp_len
        resp = conn.decrypt(resp)

        resp = json.loads(resp)
        assert resp["id"] == msg_id, "Reusing the same Noise connection across threads?"

        return resp["result"]

    def send_sigs(self, sigs, txid, deposit_outpoint, deriv_index, noise_conn=None):
        """
        Send a `sig` message to the watchtower, optionally using an existing
        connection.
        """
        params = {
            "signatures": sigs,
            "txid": txid,
            "deposit_outpoint": deposit_outpoint,
            "derivation_index": deriv_index,
        }

        resp = self.send_msg("sig", params, noise_conn)
        assert resp["txid"] == txid  # Everything is synchronous

        return resp["ack"]

    def watch_vault(self, deposit_outpoint, deposit_value, deriv_index=DERIV_INDEX):
        """The deposit transaction must be confirmed. The deposit value is in sats."""
        txs = self.get_signed_txs(deposit_outpoint, deposit_value, deriv_index)
        emer_txid = self.bitcoind.rpc.decoderawtransaction(txs["emer"]["tx"])["txid"]
        unemer_txid = self.bitcoind.rpc.decoderawtransaction(txs["unemer"]["tx"])[
            "txid"
        ]
        cancel_txid = self.bitcoind.rpc.decoderawtransaction(txs["cancel"]["tx"])[
            "txid"
        ]

        noise_conn = self.get_noise_conn()
        assert self.send_sigs(
            txs["emer"]["sigs"], emer_txid, deposit_outpoint, deriv_index, noise_conn
        )
        assert self.send_sigs(
            txs["unemer"]["sigs"],
            unemer_txid,
            deposit_outpoint,
            deriv_index,
            noise_conn,
        )
        assert self.send_sigs(
            txs["cancel"]["sigs"],
            cancel_txid,
            deposit_outpoint,
            deriv_index,
            noise_conn,
        )
        self.wait_for_log("Now watching for Unvault broadcast.")

        return txs

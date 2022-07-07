import cryptography
import json
import os
import random
import select
import socket
import threading

from nacl.public import PrivateKey as Curve25519Private
from noise.connection import NoiseConnection, Keypair
from test_framework.utils import (
    TIMEOUT,
)

HANDSHAKE_MSG = b"practical_revault_0"


class DummyCoordinator:
    """A simple in-RAM synchronization server."""

    def __init__(
        self,
        port,
        coordinator_privkey,
        client_pubkeys,
    ):
        self.port = port
        self.coordinator_privkey = coordinator_privkey
        self.coordinator_pubkey = bytes(
            Curve25519Private(coordinator_privkey).public_key
        )
        self.client_pubkeys = client_pubkeys

        # Spin up the coordinator proxy
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("localhost", self.port))
        self.s.listen(1_000)
        # Use a pipe to communicate to threads to stop
        self.r_close_chann, self.w_close_chann = os.pipe()

        # A mapping from txid to pubkey to signature
        self.sigs = {}
        # A mapping from deposit_outpoint to base64 tx
        self.spend_txs = {}

    def __del__(self):
        self.cleanup()

    def start(self):
        self.server_thread = threading.Thread(target=self.run)
        self.server_thread.start()

    def cleanup(self):
        # Write to the pipe to notify the thread it needs to stop
        os.write(self.w_close_chann, b".")
        self.server_thread.join()

    def run(self):
        """Accept new connections until we are told to stop."""
        while True:
            r_fds, _, _ = select.select([self.r_close_chann, self.s.fileno()], [], [])

            # First check if we've been told to stop, then spawn a new thread per connection
            if self.r_close_chann in r_fds:
                break
            if self.s.fileno() in r_fds:
                t = threading.Thread(target=self.connection_handle, daemon=True)
                t.start()

    def connection_handle(self):
        """Read and treat requests from this client. Blocking."""
        client_fd, _ = self.s.accept()
        client_fd.settimeout(TIMEOUT // 2)
        client_noise = self.server_noise_conn(client_fd)

        while True:
            # Manually do the select to check if we've been told to stop
            r_fds, _, _ = select.select([self.r_close_chann, client_fd], [], [])
            if self.r_close_chann in r_fds:
                break
            req = self.read_msg(client_fd, client_noise)
            if req is None:
                break
            request = json.loads(req)
            method, params = request["method"], request["params"]

            if method == "sig":
                # TODO: mutex
                if params["txid"] not in self.sigs:
                    self.sigs[params["txid"]] = {}
                self.sigs[params["txid"]][params["pubkey"]] = params["signature"]
                # TODO: remove this useless response from the protocol
                resp = {"result": {"ack": True}, "id": request["id"]}
                self.send_msg(client_fd, client_noise, json.dumps(resp))

            elif method == "get_sigs":
                txid = params["txid"]
                sigs = self.sigs.get(txid, {})
                resp = {"result": {"signatures": sigs}, "id": request["id"]}
                self.send_msg(client_fd, client_noise, json.dumps(resp))

            elif method == "set_spend_tx":
                for outpoint in params["deposit_outpoints"]:
                    self.spend_txs[outpoint] = params["spend_tx"]
                # TODO: remove this useless response from the protocol
                resp = {"result": {"ack": True}, "id": request["id"]}
                self.send_msg(client_fd, client_noise, json.dumps(resp))

            elif method == "get_spend_tx":
                spend_tx = self.spend_txs.get(params["deposit_outpoint"])
                resp = {"result": {"spend_tx": spend_tx}, "id": request["id"]}
                self.send_msg(client_fd, client_noise, json.dumps(resp))

            else:
                assert False, "Invalid request '{}'".format(method)

    def server_noise_conn(self, fd):
        """Do practical-revault's Noise handshake with a given client connection."""
        # Read the first message of the handshake only once
        data = self.read_data(fd, 32 + len(HANDSHAKE_MSG) + 16)

        # We brute force all pubkeys. FIXME!
        for pubkey in self.client_pubkeys:
            # Set the local and remote static keys
            conn = NoiseConnection.from_name(b"Noise_KK_25519_ChaChaPoly_SHA256")
            conn.set_as_responder()
            conn.set_keypair_from_private_bytes(
                Keypair.STATIC, self.coordinator_privkey
            )
            conn.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, pubkey)

            # Now, get the first message of the handshake
            conn.start_handshake()
            try:
                plaintext = conn.read_message(data)
            except cryptography.exceptions.InvalidTag:
                continue
            else:
                assert plaintext[: len(HANDSHAKE_MSG)] == HANDSHAKE_MSG

                # If it didn't fail it was the right key! Finalize the handshake.
                resp = conn.write_message()
                fd.sendall(resp)
                assert conn.handshake_finished

                return conn

        raise Exception(
            f"Unknown client key. Keys: {','.join(k.hex() for k in self.client_pubkeys)}"
        )

    def client_noise_conn(self, client_noisepriv):
        """Create a new connection to the coordinator, performing the Noise handshake."""
        conn = NoiseConnection.from_name(b"Noise_KK_25519_ChaChaPoly_SHA256")

        conn.set_as_initiator()
        conn.set_keypair_from_private_bytes(Keypair.STATIC, client_noisepriv)
        conn.set_keypair_from_private_bytes(Keypair.REMOTE_STATIC, self.coordinator_privkey)
        conn.start_handshake()

        sock = socket.socket()
        sock.settimeout(TIMEOUT // 10)
        sock.connect(("localhost", self.port))
        msg = conn.write_message(b"practical_revault_0")
        sock.sendall(msg)
        resp = sock.recv(32 + 16)  # Key size + Mac size
        assert len(resp) > 0
        conn.read_message(resp)

        return sock, conn

    def read_msg(self, fd, noise_conn):
        """read a noise-encrypted message from this stream.

        Returns None if the socket closed.
        """
        # Read first the length prefix
        cypher_header = self.read_data(fd, 2 + 16)
        if cypher_header == b"":
            return None
        msg_header = noise_conn.decrypt(cypher_header)
        msg_len = int.from_bytes(msg_header, "big")

        # And then the message
        cypher_msg = self.read_data(fd, msg_len)
        assert len(cypher_msg) == msg_len
        msg = noise_conn.decrypt(cypher_msg).decode("utf-8")
        return msg

    def send_msg(self, fd, noise_conn, msg):
        """Write a noise-encrypted message from this stream."""
        assert isinstance(msg, str)

        # Compute the message header
        msg_raw = msg.encode("utf-8")
        length_prefix = (len(msg_raw) + 16).to_bytes(2, "big")
        encrypted_header = noise_conn.encrypt(length_prefix)
        encrypted_body = noise_conn.encrypt(msg_raw)

        # Then send both the header and the message concatenated
        fd.sendall(encrypted_header + encrypted_body)

    def read_data(self, fd, max_len):
        """Read data from the given fd until there is nothing to read."""
        data = b""
        while True:
            d = fd.recv(max_len)
            if len(d) == max_len:
                return d
            if d == b"":
                return data
            data += d

    def set_spend_tx(
        self,
        manager_privkey,
        deposit_outpoints,
        spend_tx,
    ):
        """
        Send a `set_spend_tx` message to the coordinator
        """
        (sock, conn) = self.client_noise_conn(manager_privkey)
        msg_id = random.randint(0, 2 ** 32)
        msg = {
            "id": msg_id,
            "method": "set_spend_tx",
            "params": {
                "deposit_outpoints": deposit_outpoints,
                "spend_tx": spend_tx,
            }
        }

        msg_serialized = json.dumps(msg)
        self.send_msg(sock, conn, msg_serialized)

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
        assert resp["result"]["ack"]

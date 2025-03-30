from __future__ import annotations

import hashlib
import json
import secrets
import signal
import sys
from typing import Any, Dict, List

from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

from rangeproofs import (AggregNIRangeProver, AggregRangeVerifier,
                         NIRangeProver, Proof, RangeVerifier)
from utils import (ModP, b64_to_point, commitment, mod_hash, point_to_b64,
                   point_to_bytes)

CURVE = secp256k1
order = secp256k1.q
get_random_point = lambda: secrets.randbelow(order) * secp256k1.G
G = get_random_point()
H = get_random_point()
O = Point.IDENTITY_ELEMENT

U = get_random_point()
# max value 2 ** 16 - 1
n, m = 16, 2
Gs = [get_random_point() for i in range(n * m)]
Hs = [get_random_point() for i in range(n * m)]


class ProtocolParam:
    def __init__(
        self,
        G: Point,
        H: Point,
        U: Point,
        Gs: List[Point],
        Hs: List[Point],
        n: int,
        m: int,
    ):
        self.G = G
        self.H = H
        self.U = U
        self.Gs = Gs
        self.Hs = Hs
        self.n = n
        self.m = m

    def to_dict(self) -> Dict[str, Any]:
        return {
            "G": point_to_b64(self.G).decode(),
            "H": point_to_b64(self.H).decode(),
            "U": point_to_b64(self.U).decode(),
            "Gs": [point_to_b64(point).decode() for point in self.Gs],
            "Hs": [point_to_b64(point).decode() for point in self.Hs],
            "n": self.n,
            "m": self.m,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtocolParam":
        G = b64_to_point(data["G"].encode())
        H = b64_to_point(data["H"].encode())
        U = b64_to_point(data["U"].encode())
        Gs = [b64_to_point(point.encode()) for point in data["Gs"]]
        Hs = [b64_to_point(point.encode()) for point in data["Hs"]]
        n = data["n"]
        m = data["m"]

        return cls(G=G, H=H, U=U, Gs=Gs, Hs=Hs, n=n, m=m)


class RangeProofFactory:
    @staticmethod
    def aggRangeProve(
        vs: List[int], gammas: List[int], seed: bytes
    ) -> AggregNIRangeProver:
        vs = [ModP(v, order) for v in vs]
        gammas = [ModP(gamma, order) for gamma in gammas]
        return AggregNIRangeProver(vs, n, G, H, Gs, Hs, gammas, U, CURVE, seed)

    @staticmethod
    def aggRangeVerify(Vs: List[Point], proof: Proof) -> AggregRangeVerifier:
        return AggregRangeVerifier(Vs, G, H, Gs, Hs, U, proof)

    @staticmethod
    def rangeProve(v: int, gamma: int, seed: bytes) -> NIRangeProver:
        v = ModP(v, order)
        gamma = ModP(gamma, order)
        return NIRangeProver(v, n, G, H, Gs[:n], Hs[:n], gamma, U, CURVE, seed)

    @staticmethod
    def rangeVerify(V: Point, proof: Proof) -> RangeVerifier:
        return RangeVerifier(V, G, H, Gs[:n], Hs[:n], U, proof)


class UTXOSet:
    def __init__(self) -> None:
        self.utxos = set()

    def add(self, commitment: Point) -> None:
        self.utxos.add(point_to_bytes(commitment))

    def remove(self, commitment: Point) -> None:
        self.utxos.discard(point_to_bytes(commitment))

    def contains(self, commitment: Point) -> bool:
        return point_to_bytes(commitment) in self.utxos


class BlockChain:
    MIN_TX_FEE = 10

    def __init__(self) -> None:
        self.utxos = UTXOSet()
        self.txs = []
        self.accumulated_tx_fee = 0
        self.init_genesis = False

    def genesis_alloc(self, c: Point) -> int:
        if not self.init_genesis:
            self.utxos.add(c)
            self.init_genesis = True

    def get_flag(self) -> Dict[str, Any]:
        data = {}
        if (
            self.accumulated_tx_fee
            >= 0x133713371337133713371337133713371337133713371337
        ):
            data["flag"] = open("flag", "rb").read().decode()
        return data

    def verify_tx(self, tx_raw: dict) -> bool:
        try:
            tx = Transaction.from_dict(tx_raw)

            public_excess_final = tx.kernel.public_excess_final
            s = tx.kernel.sig.s
            R = tx.kernel.sig.R
            tx_fee = tx.kernel.tx_fee
            input_commitment = tx.body.input_commitment
            change_commitment = tx.body.change_commitment
            output_commitment = tx.body.output_commitment
            sender_proof = tx.proof.sender_proof
            receiver_proof = tx.proof.receiver_proof

            assert BlockChain.MIN_TX_FEE <= tx_fee < order

            # all inputs come from the current UTXO set
            assert self.utxos.contains(input_commitment)

            e = calc_challenge(R, public_excess_final, tx_fee)

            # validate parameters
            assert s.x != 0 and s.p == order and R != O and public_excess_final != O
            validation_needed_points = [
                R,
                public_excess_final,
                input_commitment,
                change_commitment,
                output_commitment,
            ]
            for point in validation_needed_points:
                assert secp256k1.is_point_on_curve((point.x, point.y))
            # validate tx_fee
            assert (
                public_excess_final
                == -input_commitment
                + change_commitment
                + output_commitment
                + tx_fee * G
            )
            # validate aggregated signatures
            assert s * H == R + e * public_excess_final
            # validate range proofs
            sender_verifier = RangeProofFactory.aggRangeVerify(
                [input_commitment, change_commitment], sender_proof
            )
            assert sender_verifier.verify()
            receiver_verifier = RangeProofFactory.rangeVerify(
                output_commitment, receiver_proof
            )
            assert receiver_verifier.verify()
        except Exception as e:
            return False

        self.txs.append(tx)

        self.utxos.remove(input_commitment)
        self.utxos.add(change_commitment)
        self.utxos.add(output_commitment)

        self.accumulated_tx_fee += tx_fee

        return True

    def propagate_tx(self):
        send_msg(self.txs[-1].to_dict())


class Signature:
    def __init__(self, s: ModP, R: Point):
        self.s = s
        self.R = R

    def to_dict(self) -> Dict[str, Any]:
        return {
            "s": self.s.to_dict(),
            "R": point_to_b64(self.R).decode(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Signature:
        s = ModP.from_dict(data["s"])
        R = b64_to_point(data["R"].encode())
        return cls(s=s, R=R)


class Kernel:
    def __init__(self, public_excess_final: Point, sig: Signature, tx_fee: int):
        self.public_excess_final = public_excess_final
        self.sig = sig
        self.tx_fee = tx_fee

    def to_dict(self) -> Dict[str, Any]:
        return {
            "public_excess_final": point_to_b64(self.public_excess_final).decode(),
            "sig": self.sig.to_dict(),
            "tx_fee": self.tx_fee,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Kernel":
        public_excess_final = b64_to_point(data["public_excess_final"].encode())
        sig = Signature.from_dict(data["sig"])
        tx_fee = data["tx_fee"]
        return cls(public_excess_final=public_excess_final, sig=sig, tx_fee=tx_fee)


class Body:
    def __init__(
        self,
        input_commitment: Point,
        change_commitment: Point,
        output_commitment: Point,
    ):
        self.input_commitment = input_commitment
        self.change_commitment = change_commitment
        self.output_commitment = output_commitment

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input": point_to_b64(self.input_commitment).decode(),
            "outputs": {
                "change": point_to_b64(self.change_commitment).decode(),
                "output": point_to_b64(self.output_commitment).decode(),
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Body:
        input_commitment = b64_to_point(data["input"].encode())
        change_commitment = b64_to_point(data["outputs"]["change"].encode())
        output_commitment = b64_to_point(data["outputs"]["output"].encode())
        return cls(
            input_commitment=input_commitment,
            change_commitment=change_commitment,
            output_commitment=output_commitment,
        )


class TransactionProof:
    def __init__(self, sender_proof: Proof, receiver_proof: Proof):
        self.sender_proof = sender_proof
        self.receiver_proof = receiver_proof

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender_proof": self.sender_proof.to_dict(),
            "receiver_proof": self.receiver_proof.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TransactionProof:
        sender_proof = Proof.from_dict(data["sender_proof"])
        receiver_proof = Proof.from_dict(data["receiver_proof"])
        return cls(sender_proof=sender_proof, receiver_proof=receiver_proof)


class Transaction:
    def __init__(self, kernel: Kernel, body: Body, proof: TransactionProof):
        self.kernel = kernel
        self.body = body
        self.proof = proof

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kernel": self.kernel.to_dict(),
            "body": self.body.to_dict(),
            "proof": self.proof.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Transaction:
        kernel = Kernel.from_dict(data["kernel"])
        body = Body.from_dict(data["body"])
        proof = TransactionProof.from_dict(data["proof"])
        return cls(kernel=kernel, body=body, proof=proof)


class AgentRequest:
    def __init__(
        self,
        input_commitment: Point,
        change_commitment: Point,
        public_nonce: Point,
        public_excess: Point,
        tx_fee: int,
        transfer_value: int,
        proof: Proof,
    ):
        self.input_commitment = input_commitment
        self.change_commitment = change_commitment
        self.public_nonce = public_nonce
        self.public_excess = public_excess
        self.tx_fee = tx_fee
        self.transfer_value = transfer_value
        self.proof = proof

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_commitment": point_to_b64(self.input_commitment).decode(),
            "change_commitment": point_to_b64(self.change_commitment).decode(),
            "public_nonce": point_to_b64(self.public_nonce).decode(),
            "public_excess": point_to_b64(self.public_excess).decode(),
            "tx_fee": self.tx_fee,
            "transfer_value": self.transfer_value,
            "proof": self.proof.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentRequest:
        """Deserialize an AgentRequest object from a dictionary."""
        input_commitment = b64_to_point(data["input_commitment"].encode())
        change_commitment = b64_to_point(data["change_commitment"].encode())
        public_nonce = b64_to_point(data["public_nonce"].encode())
        public_excess = b64_to_point(data["public_excess"].encode())
        tx_fee = data["tx_fee"]
        transfer_value = data["transfer_value"]
        proof = Proof.from_dict(data["proof"])
        assert isinstance(tx_fee, int) and isinstance(transfer_value, int)

        return cls(
            input_commitment,
            change_commitment,
            public_nonce,
            public_excess,
            tx_fee,
            transfer_value,
            proof,
        )


class AgentResponse:
    def __init__(
        self,
        output_commitment: Point,
        public_nonce: Point,
        signature: ModP,
        public_key: Point,
        proof: Proof,
    ):
        self.output_commitment = output_commitment
        self.public_nonce = public_nonce
        self.signature = signature
        self.public_key = public_key
        self.proof = proof

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the AgentResponse object to a dictionary."""
        return {
            "output_commitment": point_to_b64(self.output_commitment).decode(),
            "public_nonce": point_to_b64(self.public_nonce).decode(),
            "signature": self.signature.to_dict(),
            "public_key": point_to_b64(self.public_key).decode(),
            "proof": self.proof.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentResponse:
        """Deserialize an AgentResponse object from a dictionary."""
        output_commitment = b64_to_point(data["output_commitment"].encode())
        public_nonce = b64_to_point(data["public_nonce"].encode())
        signature = ModP.from_dict(data["signature"])
        public_key = b64_to_point(data["public_key"].encode())
        proof = Proof.from_dict(data["proof"])

        return cls(output_commitment, public_nonce, signature, public_key, proof)


class Agent:
    def __init__(self, name: bytes, value: int, pk: int):
        self.name = name
        self.value = value
        self.pk = pk

        self.new_pk = None

        self.nonce = None
        self.excess = None

    # Alice prepares the transaction
    def request(self, tx_fee: int, transfer_value: int) -> dict:
        k1 = secrets.randbelow(order)
        input_commitment = commitment(G, H, self.value, self.pk)
        change_commitment = commitment(G, H, self.value - tx_fee - transfer_value, k1)

        # sanity check range proof
        proof = RangeProofFactory.aggRangeProve(
            [self.value, self.value - tx_fee - transfer_value], [self.pk, k1], self.name
        ).prove()
        proof = Proof.from_dict(proof.to_dict())
        assert RangeProofFactory.aggRangeVerify(
            [input_commitment, change_commitment], proof
        ).verify()

        excess = k1 - self.pk
        public_excess = excess * H
        assert (
            public_excess
            == -input_commitment + change_commitment + (transfer_value + tx_fee) * G
        )
        self.new_pk = k1
        r_a = secrets.randbelow(order)
        R_a = r_a * H

        request = AgentRequest(
            input_commitment=input_commitment,
            change_commitment=change_commitment,
            public_nonce=R_a,
            public_excess=public_excess,
            tx_fee=tx_fee,
            transfer_value=transfer_value,
            proof=proof,
        )

        data = {}
        data["sender"] = request.to_dict()

        self.nonce = r_a
        self.excess = excess
        return data

    # Bob prepares his response
    def response(self, data: dict) -> dict:
        request = AgentRequest.from_dict(data["sender"])

        public_excess = request.public_excess
        input_commitment = request.input_commitment
        change_commitment = request.change_commitment
        R_a = request.public_nonce
        tx_fee = request.tx_fee
        transfer_value = request.transfer_value

        assert (
            public_excess
            == -input_commitment + change_commitment + (transfer_value + tx_fee) * G
        )
        # Spending key for bob
        k_b = self.pk
        output_commitment = commitment(G, H, transfer_value, k_b)

        # sanity check range proof
        proof = RangeProofFactory.rangeProve(transfer_value, k_b, self.name).prove()
        proof = Proof.from_dict(proof.to_dict())
        assert RangeProofFactory.rangeVerify(output_commitment, proof).verify()

        P_b = k_b * H
        r_b = secrets.randbelow(order)
        self.nonce = r_b

        R_b = r_b * H
        public_excess_final = public_excess + P_b
        e = calc_challenge(R_a + R_b, public_excess_final, tx_fee)
        s_b = r_b + e * k_b

        response = AgentResponse(
            output_commitment=output_commitment,
            public_nonce=R_b,
            signature=ModP(s_b, order),
            public_key=P_b,
            proof=proof,
        )

        data["receiver"] = response.to_dict()

        self.value = transfer_value
        return data

    # Alice completes the tx
    def finalize_tx(self, data: dict) -> dict:
        request = AgentRequest.from_dict(data["sender"])
        response = AgentResponse.from_dict(data["receiver"])

        R_a = request.public_nonce
        R_b = response.public_nonce
        public_excess = request.public_excess
        P_b = response.public_key
        s_b = response.signature
        tx_fee = request.tx_fee

        public_excess_final = public_excess + P_b
        e = calc_challenge(R_a + R_b, public_excess_final, tx_fee)
        s_a = self.nonce + e * self.excess
        # aggregate signs
        s = s_a + s_b
        R = R_a + R_b

        signature = Signature(s=s, R=R)
        kernel = Kernel(
            public_excess_final=public_excess_final,
            sig=signature,
            tx_fee=tx_fee,
        )
        body = Body(
            input_commitment=request.input_commitment,
            change_commitment=request.change_commitment,
            output_commitment=response.output_commitment,
        )
        proof = TransactionProof(
            sender_proof=request.proof,
            receiver_proof=response.proof,
        )

        return Transaction(kernel=kernel, body=body, proof=proof).to_dict()


def calc_challenge(R: Point, X: Point, f: int) -> int:
    msg = point_to_bytes(R) + point_to_bytes(X) + f.to_bytes(32, byteorder="big")
    e = mod_hash(msg, order).x
    return e


def send_msg(data: Dict):
    sys.stdout.write(json.dumps(data) + "\n")
    sys.stdout.flush()


def recv_msg() -> Dict[str, Any]:
    data = sys.stdin.readline().strip()
    return json.loads(data)


if __name__ == "__main__":
    PROTOCOL_PARAM = ProtocolParam(G=G, H=H, U=U, Gs=Gs, Hs=Hs, n=n, m=m)

    ####  onchain  ####
    send_msg(PROTOCOL_PARAM.to_dict())
    chain = BlockChain()
    ###################

    signal.alarm(30)

    #### offchain  ####
    alice_initial_value = 300
    # Spending key for alice
    k_a = secrets.randbelow(order)
    initial_commitment = commitment(G, H, alice_initial_value, k_a)
    chain.genesis_alloc(initial_commitment)
    # Alice prepares the transaction
    tx_fee, transfer_value = 10, 200
    alice = Agent(b"alice", alice_initial_value, k_a)
    alice_data = alice.request(tx_fee, transfer_value)
    # Spending key for bob
    k_b = secrets.randbelow(order)
    bob = Agent(b"bob", 0, k_b)
    bob_data = bob.response(alice_data)
    tx_raw = alice.finalize_tx(bob_data)
    ###################

    ####  onchain  ####
    assert chain.verify_tx(tx_raw)
    chain.propagate_tx()
    ###################

    #### offchain  ####
    send_msg({"k_b": k_b})
    ###################

    ####  onchain  ####
    tx_raw_2 = recv_msg()
    assert chain.verify_tx(tx_raw_2)
    send_msg(chain.get_flag())
    ###################

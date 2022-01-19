import json
from io import BytesIO
from typing import List
from helper import SIGHASH_ALL
import requests

from helper import little_endian_to_int, read_varint, hash256, int_to_little_endian, encode_varint
from script import Script
from ecc import S256Point, Signature


class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if not script_sig:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def fetch(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet)

    def value(self, testnet=False):
        tx = self.fetch(testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pub_key(self, testnet=False):
        tx = self.fetch(testnet)
        return tx.tx_outs[self.prev_index].script_pubkey

    @classmethod
    def parse(cls, stream):
        prev_tx = stream.read(32)[::-1]
        prev_index = little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = little_endian_to_int(stream.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def __repr__(self):
        return '{}:{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
            self.script_sig
        )


class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    @classmethod
    def parse(cls, stream):
        amount = little_endian_to_int(stream.read(8))
        script_pub_key = Script.parse(stream)
        return cls(amount, script_pub_key)

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    def serialize(self):
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result


# tag::source7[]
class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://blockstream.info/testnet/api/'
        else:
            return 'https://blockstream.info/api/'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}/hex'.format(cls.get_url(testnet), tx_id)
            print(f"TxFetcher fetch transactions: {url}\n")
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:  # <1>
                raise ValueError('not the same id: {} vs {}'.format(tx.id(),
                                                                    tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    # end::source7[]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)


class Tx:
    def __init__(self, version, tx_ins: List[TxIn], tx_outs: List[TxOut], locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def fee(self):
        inputs_sum = sum([x.value(self.testnet) for x in self.tx_ins])
        outputs_sum = sum([x.amount for x in self.tx_outs])
        return inputs_sum - outputs_sum

    def sig_hash(self, input_index):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                result += TxIn(prev_tx=tx_in.prev_tx, prev_index=tx_in.prev_index,
                               script_sig=tx_in.script_pub_key(self.testnet), sequence=tx_in.sequence).serialize()
            else:
                result += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    sequence=tx_in.sequence,
                ).serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        result += int_to_little_endian(SIGHASH_ALL, 4)
        return int.from_bytes(hash256(result), 'big')

    def verify_input(self, input_index):
        sig_hash = self.sig_hash(input_index)
        tx_in = self.tx_ins[input_index]
        combined_script = tx_in.script_sig + tx_in.script_pub_key(testnet=self.testnet)
        print("verify input sig_hash {}, combined_script: {} len: {}\n\n".format(sig_hash, combined_script.cmds, len(combined_script.cmds)))
        return combined_script.evaluate(sig_hash)

    def verify(self):
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    @classmethod
    def parse(cls, stream, testnet=False):
        serialized_version = stream.read(4)
        version = little_endian_to_int(serialized_version)
        tx_in_number = read_varint(stream)
        tx_ins = []
        for tx_in in range(tx_in_number):
            tx_ins.append(TxIn.parse(stream))
        tx_out_number = read_varint(stream)
        tx_outs = []
        for tx_out in range(tx_out_number):
            tx_outs.append(TxOut.parse(stream))
        locktime = little_endian_to_int(stream.read(4))
        print("parse tx: version: {}, locktime: {}".format(version, locktime))
        for tx_in in tx_ins:
            print(f"tx_in: {tx_in}\n")
        for tx_out in tx_outs:
            print(f"tx_out: {tx_out}\n")
        return cls(version, tx_ins, tx_outs, locktime, testnet)

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self):
        return self.hash().hex()

    def hash(self):
        return hash256(self.serialize())[::-1]

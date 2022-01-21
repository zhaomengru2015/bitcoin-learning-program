from hashlib import sha256
from io import BytesIO

from helper import read_varint, little_endian_to_int, int_to_little_endian, encode_varint
from op import OP_CODE_FUNCTIONS, OP_CODE_NAMES, LOGGER, op_hash160, op_equal, op_verify


class Script:
    def __init__(self, cmds=None):
        if not cmds:
            cmds = []
        self.cmds = cmds

    def is_p2pkh_script_pubkey(self):
        '''Returns whether this follows the
        OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern.'''
        return len(self.cmds) == 5 and self.cmds[0] == 0x76 \
               and self.cmds[1] == 0xa9 \
               and type(self.cmds[2]) == bytes and len(self.cmds[2]) == 20 \
               and self.cmds[3] == 0x88 and self.cmds[4] == 0xac

    def is_p2sh_script_pubkey(self):
        '''Returns whether this follows the
        OP_HASH160 <20 byte hash> OP_EQUAL pattern.'''
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 \
               and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20 \
               and self.cmds[2] == 0x87

    def is_p2wpkh_script_pubkey(self):
        # OP_0 <20 byte hash>
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 \
               and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    @classmethod
    def parse(cls, s):
        len = read_varint(s)  # total bytes
        cmds = []
        count = 0  # processed bytes
        while count < len:
            current = s.read(1)
            count += 1
            current_byte = current[0]
            # 0x01 ~ 0x75 is the length to be read
            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                op_code = current_byte
                cmds.append(op_code)
        if count != len:
            raise SyntaxError('parsing script failed')
        return Script(cmds)

    def raw_serialize(self):
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    # OP_PUSHDATA1
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:
                    result += int_to_little_endian(77, 1)
                    # OP_PUSHDATA2
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long an cmd')
                result += cmd
        return result

    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    def serialize(self):
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        # get the length of the whole thing
        total = len(result)
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result

    def evaluate(self, z, witness):
        # create a copy as we may need to add to this list if we have a
        # RedeemScript
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                # do what the opcode says
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    # op_if/op_notif require the cmds array
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                # add the cmd to the stack
                stack.append(cmd)
                # p2sh rule. if the next three cmds are:
                # OP_HASH160 <20 byte hash> OP_EQUAL this is the RedeemScript
                # OP_HASH160 == 0xa9 and OP_EQUAL == 0x87
                if len(cmds) == 3 and cmds[0] == 0xa9 \
                        and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
                        and cmds[2] == 0x87:
                    redeem_script = encode_varint(len(cmd)) + cmd
                    # we execute the next three opcodes
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    # final result should be a 1
                    if not op_verify(stack):
                        LOGGER.info('bad p2sh h160')
                        return False
                    # hashes match! now add the RedeemScript
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)
                # witness program version 0 rule. if stack cmds are:
                # 0 <20 byte hash> this is p2wpkh
                # tag::source3[]
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 20:  # <1>
                    h160 = stack.pop()
                    stack.pop()
                    cmds.extend(witness)
                    cmds.extend(p2pkh_script(h160).cmds)
                # end::source3[]
                # witness program version 0 rule. if stack cmds are:
                # 0 <32 byte hash> this is p2wsh
                # tag::source6[]
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 32:
                    s256 = stack.pop()  # <1>
                    stack.pop()  # <2>
                    cmds.extend(witness[:-1])  # <3>
                    witness_script = witness[-1]  # <4>
                    if s256 != sha256(witness_script):  # <5>
                        print('bad sha256 {} vs {}'.format
                              (s256.hex(), sha256(witness_script).hex()))
                        return False
                    stream = BytesIO(encode_varint(len(witness_script))
                                     + witness_script)
                    witness_script_cmds = Script.parse(stream).cmds  # <6>
                    cmds.extend(witness_script_cmds)
                # end::source6[]
        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True

    def serialize(self):
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result


def p2pkh_script(h160):
    return Script([0x76, 0xa9, h160, 0x88, 0xac])

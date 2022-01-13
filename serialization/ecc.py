from random import randint

from helper import hash160, encode_base58_checksum


class FiniteElement:
    def __init__(self, num, prime):
        self.num = num
        self.prime = prime

    def __repr__(self):
        return f'FiniteElement_{self.prime}_{self.num}'

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        num = (self.num + other.num) % self.prime
        return self.__class__(num=num, prime=self.prime)

    def __sub__(self, other):
        num = (self.num - other.num) % self.prime
        return self.__class__(num=num, prime=self.prime)

    def __mul__(self, other):
        num = (self.num * other.num) % self.prime
        return self.__class__(num=num, prime=self.prime)

    def __pow__(self, exponent):
        num = (self.num ** exponent) % self.prime
        return self.__class__(num=num, prime=self.prime)

    def __truediv__(self, other):
        num = self.num * pow(other.num, self.prime - 2, self.prime) % self.prime
        return self.__class__(num=num, prime=self.prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)


P = 2 ** 256 - 2 ** 32 - 977


class S256Field(FiniteElement):
    def __init__(self, num, prime=None):
        super().__init__(num, prime=P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        return self ** ((P + 1) / 4)


class Point:
    def __init__(self, a, b, x, y):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if pow(y, 2) != pow(x, 3) + a * x + b:
            raise ValueError("init point failed")

    def __eq__(self, other):
        return True if self.y == other.y and self.x == other.x and self.a == other.a and self.b == other.b else False

    def __ne__(self, other):
        return not self == other

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise ValueError("a or b does not match")
        # 任何点和I点相加还是其本身
        if self.x is None:
            return other
        if other.x is None:
            return self
        # 两个点关于x轴对称，相加是I点
        if self.x == other.x and self.y != other.y:
            return self.__class__(a=self.a, b=self.b, x=None, y=None)
        # 两个不同的点相加，但是不关于x轴对称。(x3,y3)==(x1,y1)+(x2,y2)
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = pow(s, 2) - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(a=self.a, b=self.b, x=x, y=y)
        # 同一个点相加，如果这个点是y值为0的点，则相加的结果为I
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        # 同一个点相加，这个点不是y值为0的点。(x3,y3)=(x1,y1)+(x1,y1)
        if self == other:
            s = (3 * pow(self.x, 2) + self.a) / (2 * self.y)
            x = pow(s, 2) - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(a=self.a, b=self.b, x=x, y=y)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(a=self.a, b=self.b, x=None, y=None)  # <2>
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FiniteElement):
            return 'Point({},{})_{}_{} FiniteElement({})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)


A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)

    def der(self):
        rbin = self.r.to_bytes(32, byteorder='big')
        rbin = rbin.lstrip(b'\x00')
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin
        # sbin = self.s.to_bytes(32, byteorder='big')
        # result = b'0x30'
        sbin = self.s.to_bytes(32, byteorder='big')
        sbin = sbin.lstrip(b'\x00')
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result


class PrivateKey:
    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z):
        k = randint(0, N)
        k_inv = pow(k, N - 2, N)
        r = (k * G).x.num
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    def wif(self, compressed=True, testnet=False):
        if testnet:
            result = b'\xef'
        else:
            result = b'\x80'
        result += self.secret.to_bytes(32, 'big')
        if compressed:
            result += b'\x01'
        return encode_base58_checksum(result)


class S256Point(Point):
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(a=a, b=b, x=S256Field(x), y=S256Field(y))
        else:
            super().__init__(a=a, b=b, x=x, y=y)

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)

    def verify(self, z, sig):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        try:
            if (u * G + v * self).x.num == sig.r:
                return True
        except ValueError:
            return False

    def sec(self, compressed=True):
        if not compressed:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')

    @classmethod
    def parse(cls, sec_bin):
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x, y)
        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        alpha = x ** 3 + S256Field(B)
        beta = alpha.sqrt()
        if beta % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            odd_beta = beta
            even_beta = S256Field(P - beta.num)
        if is_even:
            return S256Point(x, odd_beta)
        else:
            return S256Point(x, odd_beta)

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

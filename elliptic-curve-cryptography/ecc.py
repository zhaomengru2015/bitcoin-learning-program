from random import randint


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
        # ????????????I????????????????????????
        if self.x is None:
            return other
        if other.x is None:
            return self
        # ???????????????x?????????????????????I???
        if self.x == other.x and self.y != other.y:
            return self.__class__(a=self.a, b=self.b, x=None, y=None)
        # ??????????????????????????????????????????x????????????(x3,y3)==(x1,y1)+(x2,y2)
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = pow(s, 2) - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(a=self.a, b=self.b, x=x, y=y)
        # ???????????????????????????????????????y??????0??????????????????????????????I
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        # ????????????????????????????????????y??????0?????????(x3,y3)=(x1,y1)+(x1,y1)
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


G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

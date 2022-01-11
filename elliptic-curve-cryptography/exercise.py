"""
Exercise 1
y² = x³ + 7 over F₂₂₃
验证这些点在曲线上(192,105), (17,56), (200,119), (1,193), (42,99)
"""
from ecc import FiniteElement, Point, S256Point, N, G, Signature
from helper import hash256


def exercise_1():
    prime = 223
    a = FiniteElement(0, prime)
    b = FiniteElement(7, prime)
    points = ((192, 105), (17, 56), (200, 119), (1, 193), (42, 99))
    for each in points:
        x = FiniteElement(num=each[0], prime=prime)
        y = FiniteElement(num=each[1], prime=prime)
        try:
            print("point {} is on the curve\n".format(Point(a, b, x, y)))
        except ValueError:
            print("point {},{} not on the curve\n".format(each[0], each[1]))


def exercise_3():
    prime = 223
    a = FiniteElement(0, prime)
    b = FiniteElement(7, prime)
    points = (((170, 142), (60, 139)), ((47, 71), (17, 56)), ((143, 98), (76, 66)))
    for point in points:
        left, right = point
        left_x = FiniteElement(num=left[0], prime=prime)
        left_y = FiniteElement(num=left[1], prime=prime)
        right_x = FiniteElement(num=right[0], prime=prime)
        right_y = FiniteElement(num=right[1], prime=prime)
        try:
            left_point = Point(a, b, left_x, left_y)
            right_point = Point(a, b, right_x, right_y)
            result = left_point + right_point
            print(f"({left_x.num, left_y.num})+({right_x.num, right_y.num})=({result.x.num},{result.y.num})")
        except ValueError:
            print("point is not on curve")
            continue


def exercise_4():
    prime = 223
    a = FiniteElement(0, prime)
    b = FiniteElement(7, prime)
    points = ((192, 105, 2), (143, 98, 2), (47, 71, 2), (47, 71, 4), (47, 71, 8), (47, 71, 21))
    for point in points:
        point_x = FiniteElement(point[0], prime)
        point_y = FiniteElement(point[1], prime)
        result = Point(a, b, None, None)
        for i in range(point[2]):
            result = result + Point(a, b, point_x, point_y)
        print(f"{point[2]}*({point_x.num, point_y.num})=({result})")


def exercise_5():
    prime = 223
    a = FiniteElement(0, prime)
    b = FiniteElement(7, prime)
    x = FiniteElement(15, prime)
    y = FiniteElement(86, prime)
    p = Point(x=x, y=y, a=a, b=b)
    inf = Point(x=None, y=None, a=a, b=b)
    product = p
    count = 1
    while product != inf:
        product += p
        count += 1
    print(count)


def exercise_6():
    P = (0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
         0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
    data = ((0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60,
             0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395,
             0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4), (
                0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d,
                0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c,
                0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6))
    for each in data:
        (z, r, s) = each
        point = S256Point(P[0], P[1])
        s_inv = pow(s, N - 2, N)
        u = z * s_inv % N
        v = r * s_inv % N
        try:
            if (u * G + v * point).x.num == r:
                print(f"signature {s} is valid\n")
        except ValueError:
            print(f"signature {s} is invalid\n")


def exercise_7():
    e = 12345
    z = int.from_bytes(hash256(b'Programming Bitcoin!'), 'big')
    k = 1234567890
    k_inv = pow(k, N - 2, N)
    P = e * G
    r = (k * G).x.num
    s = (z + r * e) * k_inv % N
    sig = Signature(r, s)
    P.verify(z, sig)


if __name__ == '__main__':
    print("***********Exercise 1************\n\n")
    exercise_1()
    print("***********Exercise 3************\n\n")
    exercise_3()
    print("***********Exercise 4************\n\n")
    exercise_4()
    print("***********Exercise 5************\n\n")
    exercise_5()
    print("***********Exercise 6************\n\n")
    exercise_6()
    print("***********Exercise 7************\n\n")
    exercise_7()

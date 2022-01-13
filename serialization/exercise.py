from ecc import PrivateKey, Signature
from helper import encode_base58


def exercise1():
    secrets = (5000, pow(2018, 5), 0xdeadbeef12345)
    for e in secrets:
        priv_key = PrivateKey(e)
        print(f"SEC for private key {priv_key} is: {priv_key.point.sec(compressed=False).hex()}")


def exercise2():
    secrets = (5001, pow(2019, 5), 0xdeadbeef54321)
    for e in secrets:
        priv_key = PrivateKey(e)
        print(f"SEC for private key {priv_key} is: {priv_key.point.sec().hex()}")


def exercise3():
    r = 0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6
    s = 0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec
    sig = Signature(r, s)
    print(sig.der().hex())


def exercise4():
    data = ('7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d',
            'eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c',
            'c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6')
    for each in data:
        print(f"base58 encode for {each} is: {encode_base58(bytes.fromhex(each))}")


def exercise5():
    private_keys = ((5002, False, True), (pow(2020, 5), True, True), (0x12345deadbeef, True, False))
    for each in private_keys:
        private_key = PrivateKey(each[0])
        print(f"compressed address {private_key.point.address(compressed=each[1], testnet=each[2])}")


def exercise6():
    private_keys = ((5003, True, True), (pow(2021, 5), False, True), (0x54321deadbeef, True, False))
    for each in private_keys:
        key = PrivateKey(each[0])
        print(f"WIF format for {each[0]} is: {key.wif(each[1], each[2])}")


def exercise9():
    private_key = PrivateKey(202201141554)
    address = private_key.point.address(compressed=True, testnet=True)
    print(f"my address is {address}")


if __name__ == '__main__':
    print("***********Exercise 1************\n\n")
    exercise1()
    print("***********Exercise 2************\n\n")
    exercise2()
    print("***********Exercise 3************\n\n")
    exercise3()
    print("***********Exercise 4************\n\n")
    exercise4()
    print("***********Exercise 5************\n\n")
    exercise5()
    print("***********Exercise 6************\n\n")
    exercise6()
    print("***********Exercise 9************\n\n")
    exercise9()

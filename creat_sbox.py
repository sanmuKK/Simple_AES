from gf import mul
import numpy


def division(a, b):
    len1 = len(bin(a)[2:])
    len2 = len(bin(b)[2:])
    len3 = len1 - len2
    if a < b:
        if len3 == 0:
            return 1, a ^ b
        else:
            return 0, a
    top_bit = 1
    top_bit <<= (len1 - 1)
    b <<= len3
    quotient = 0
    for i in range(len3):
        quotient <<= 1
        if top_bit & a:
            quotient ^= 1
            a ^= b
        else:
            a ^= 0
        top_bit >>= 1
        b >>= 1
    quotient <<= 1
    if a < b:
        remainder = a
    else:
        quotient ^= 1
        remainder = a ^ b

    return quotient, remainder


def Inv_gcd(a, b):
    r0, r1, s0, s1 = 1, 0, 0, 1
    while b:
        qt, rt = division(a, b)
        q, a, b = qt, b, rt
        r0, r1 = r1, r0 ^ int(mul(hex(q)[2:], hex(r1)[2:], '11B'), 16)
        s0, s1 = s1, s0 ^ int(mul(hex(q)[2:], hex(s1)[2:], '11B'), 16)
    return s0


def byteSub(x):
    m = [0x1F, 0x3E, 0x7C, 0xF8, 0xF1, 0xE3, 0xC7, 0x8F]
    res = 0x00
    i = 0
    while x > 0:
        if x % 2:
            res ^= m[i]
        i += 1
        x >>= 1
    return res ^ 0x63


def Inv_byteSub(x):
    m = [0xA4, 0x49, 0x92, 0x25, 0x4A, 0x94, 0x29, 0x52]
    res = 0x00
    i = 0
    while x > 0:
        if x % 2:
            res ^= m[i]
        i += 1
        x >>= 1
    return res ^ 0x05


def sBox():
    box = []
    for i in range(256):
        s_box = hex(byteSub(Inv_gcd(283, i))).upper()
        box.append(s_box)
    return box


def resBox():
    re_box = []
    for i in range(256):
        s_box = hex(Inv_gcd(283, Inv_byteSub(i))).upper()
        re_box.append(s_box)
    re_box = numpy.array(re_box).reshape(16, 16).T
    re_box2 = []
    for i in re_box:
        for j in i:
            re_box2.append(j)
    return re_box2

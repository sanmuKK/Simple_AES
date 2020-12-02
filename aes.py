import numpy
from Crypto.Util.number import long_to_bytes
from gf import poly_mul, gf_mod
from creat_sbox import sBox, resBox


def transform(x, nb):
    a = []
    for i in x:
        a.append(hex(i)[2:])
    return numpy.array(a).reshape(nb, 4).T


def bin_xor(x, y):
    z = int(str(x), 16) ^ int(str(y), 16)
    z = gf_mod(hex(z)[2:], '100')
    return z


def ByteSub(x):
    x = x.rjust(2, '0')
    y = int(x[0], 16) * 16 + int(x[1], 16)
    return s_box[y][2:].rjust(2, '0')


def InvByteSub(x):
    x = x.rjust(2, '0')
    y = int(x[0], 16) * 16 + int(x[1], 16)
    return ReS_Table[y][2:].rjust(2, '0')


def Addition_Round_Key(x, y, nb):
    for i in range(0, 4):
        for j in range(0, nb):
            x[i][j] = hex(int(x[i][j], 16) ^ int(y[i][j], 16))[2:].rjust(2, '0')
    return x


def generate_secret(x, nb, nk):
    key = transform(x, nk)
    a = numpy.array(key).reshape(4, nk)
    k = [a]
    if nb == 4 and nk == 4:
        rou = 10
    elif nk == 8 or nb == 8:
        rou = 14
    else:
        rou = 12
    alli = rou + (nb - nk) * rou // nk + 1
    for i in range(0, alli):
        temp = [
            ByteSub(a[1][nk - 1]), ByteSub(a[2][nk - 1]),
            ByteSub(a[3][nk - 1]), ByteSub(a[0][nk - 1])
        ]
        ff = i
        r = 1
        while ff > 0:
            r *= 2
            ff -= 1
        temp[0] = bin_xor(temp[0], hex(r)[2:])
        list2 = temp
        list_i = []
        for j in range(0, nk):
            if nk > 6 and j == 3:
                list2 = [
                    ByteSub(list2[0]), ByteSub(list2[1]),
                    ByteSub(list2[2]), ByteSub(list2[3])
                ]
            list3 = [
                bin_xor(list2[0], a[0][j]).rjust(2, '0'), bin_xor(list2[1], a[1][j]).rjust(2, '0'),
                bin_xor(list2[2], a[2][j]).rjust(2, '0'), bin_xor(list2[3], a[3][j]).rjust(2, '0'),
            ]
            list_i.append(list3)
            list2 = list3
        list_i = numpy.array(list_i)
        a = list_i.T
        k.append(a)
    t = []
    for i in range(0, len(k)):
        for j in range(0, nk):
            for kk in range(0, 4):
                t.append(k[i][kk][j])
    tt = []
    net = nb * (rou + 1) * 4
    while len(t) - net > 0:
        t.pop()
    for i in range(0, len(t), 4*nb):
        tt.append(numpy.array(t[i:i+4*nb]).reshape(nb, 4).T)
    return tt


def Shiftnb(x):
    for i in range(1, 4):
        x[i] = numpy.roll(x[i], -i)
    return x


def InvShiftnb(x):
    for i in range(1, 4):
        x[i] = numpy.roll(x[i], i)
    return x


def Mixnkum(x, nb):
    for iii in range(0, nb):
        right = ''
        for i in range(3, -1, -1):
            right += x[i][iii]
        right = long_to_bytes(int(right, 16))
        left = b'\x03\x01\x01\x02'
        ans = poly_mul(left, right)
        for i, j in zip(range(0, 4), range(3, -1, -1)):
            x[i][iii] = hex(ans[j])[2:]
    return x


def InvMixcnkumn(x, nb):
    for iii in range(0, nb):
        right = ''
        for i in range(3, -1, -1):
            right += x[i][iii]
        right = long_to_bytes(int(right, 16))
        left = b'\x0b\x0d\x09\x0e'
        ans = poly_mul(left, right)
        for i, j in zip(range(0, 4), range(3, -1, -1)):
            x[i][iii] = hex(ans[j])[2:]
    return x


def encrypt(plain, keys, nb, nk):
    result = ''
    list_p = transform(plain, nb)
    key_list = generate_secret(keys, nb, nk)
    list_p = Addition_Round_Key(list_p, key_list[0], nb)
    if nb == 4 and nk == 4:
        rou = 10
    elif nb == 8 or nk == 8:
        rou = 14
    else:
        rou = 12
    for i in range(0, rou - 1):
        for j in range(0, 4):
            for k in range(0, nb):
                list_p[j][k] = ByteSub(list_p[j][k])
        list_p = Shiftnb(list_p)
        list_p = Mixnkum(list_p, Nb)
        list_p = Addition_Round_Key(list_p, key_list[i + 1], nb)
    for j in range(0, 4):
        for k in range(0, nb):
            list_p[j][k] = ByteSub(list_p[j][k])
    list_p = Shiftnb(list_p)
    list_p = Addition_Round_Key(list_p, key_list[10], nb)
    for j in range(0, nb):
        for i in range(0, 4):
            result += list_p[i][j]
    return result


def decrypt(cipher, keys, nb, nk):
    result = ''
    list_p = transform(cipher, nb)
    key_list = generate_secret(keys, nb, nk)
    list_p = Addition_Round_Key(list_p, key_list[10], nb)
    list_p = InvShiftnb(list_p)
    for j in range(0, 4):
        for k in range(0, nb):
            list_p[j][k] = InvByteSub(list_p[j][k])
    if nb == 4 and nk == 4:
        rou = 10
    elif nb == 8 or nk == 8:
        rou = 14
    else:
        rou = 12
    for i in range(rou - 2, -1, -1):
        list_p = Addition_Round_Key(list_p, key_list[i + 1], nb)
        list_p = InvMixcnkumn(list_p, Nb)
        list_p = InvShiftnb(list_p)
        for j in range(0, 4):
            for k in range(0, nb):
                list_p[j][k] = InvByteSub(list_p[j][k])
    list_p = Addition_Round_Key(list_p, key_list[0], nb)
    for j in range(0, nb):
        for i in range(0, 4):
            result += chr(int(list_p[i][j], 16))
    return result


def main(plain, keys, nb, nk):
    cipher = ''
    plain = plain.ljust(16, b'0')
    keys = keys.ljust(16, b'0')
    for i, j in zip(range(0, len(plain), nb * 4), range(0, len(keys), nk * 4)):
        c1 = plain[i:i + nb * 4].ljust(nb * 4, b'0')
        k1 = keys[j:j + nk * 4].ljust(nk * 4, b'0')
        cipher += str(encrypt(c1, k1, nb, nk))
    return cipher


def main2(cipher, keys, nb, nk):
    plain = ''
    cipher.ljust(16, b'0')
    keys.ljust(16, b'0')
    for i, j in zip(range(0, len(cipher), nb * 4), range(0, len(keys), nk * 4)):
        c1 = cipher[i:i + nb * 4].ljust(nb * 4, b'0')
        k1 = keys[j:j + nk * 4].ljust(nk * 4, b'0')
        plain += str(decrypt(c1, k1, nb, nk))
    return plain


if __name__ == '__main__':
    plain_text = input("明文:")
    secret_key = input("密钥:")
    Nb = int(input("Nb:"))
    Nk = int(input("Nk:"))
    print("待加密的明文为:", plain_text)
    secret_key = bytes(secret_key, encoding='utf-8')
    plain_text = bytes(plain_text, encoding='utf-8')
    s_box = sBox()
    ReS_Table = resBox()
    c = main(plain_text, secret_key, Nb, Nk)
    print("加密后的密文为:", c)
    print("待加密的明文为:", c)
    cr = long_to_bytes(int(c, 16))
    d = main2(cr, secret_key, Nb, Nk)
    print("解密后的明文为:", d)

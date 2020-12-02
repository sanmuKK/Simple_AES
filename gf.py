from Crypto.Util.number import long_to_bytes


def gf_mod(hex_num, m=None):
    if m:
        gf_mod_num = int(hex_num, 16) % int(m, 16)
    else:
        gf_mod_num = int(hex_num, 16)
    return hex(gf_mod_num)[2:]


def xor_bin(left, right):
    result = int(left, 2) ^ int(right, 2)
    return bin(result)[2:].rjust(len(left), '0')


def add(left, right):
    left = bin(int(left, 16))[2:]
    right = bin(int(right, 16))[2:]
    return gf_mod(hex(int(xor_bin(left, right), 2))[2:], '100')


def x_time(x, m):
    y = int(x, 16)
    x = bin(y << 1)[2:]
    if len(x) > 8:
        x = x[1:]
        x = bin(int(x, 2) ^ int('1B', 16))[2:]
    x = hex(int(x, 2))[2:]
    x = gf_mod(x, m)
    return x


def mul(x, y, m):
    z = bin(int(y, 16))[2:]
    w = x
    if z[-1] == '0':
        x = '0'
    for ii in range(len(z) - 2, -1, -1):
        w = x_time(w, m)
        if z[ii] == '1':
            x = hex(int(x, 16) ^ int(w, 16))[2:]
    x = gf_mod(x, m)
    return x


def poly_add(x, y):
    len_l = len(x)
    x = hex(int(x, 2))[2:]
    y = hex(int(y, 2))[2:]
    z = add(x, y)
    return bin(int(z, 16))[2:].rjust(len_l, '0')


def poly_mul(x, y):
    ans = ''
    lx = 4 - len(x)
    ly = 4 - len(y)
    while lx > 0:
        x = b'\x00' + x
        lx -= 1
    while ly > 0:
        y = b'\x00' + y
        ly -= 1
    for i in range(3, -1, -1):
        z = mul(hex(x[i])[2:], hex(y[3])[2:], '11B').rjust(2, '0')
        xi = i
        yi = 3
        for j in range(1, 4):
            xi = (xi + 1) % 4
            yi -= 1
            t = mul(hex(x[xi])[2:], hex(y[yi])[2:], '11B').rjust(2, '0')
            z = hex(int(z, 16) ^ int(t, 16))[2:].rjust(2, '0')
        ans = z + ans
    ans = long_to_bytes(int(ans, 16))
    la = 4 - len(ans)
    while la > 0:
        ans = b'\x00' + ans
        la -= 1
    return ans


if __name__ == '__main__':
    a = input("a:")
    b = input("b:")
    c = add(a, b)
    print("a+b =", c)
    d = mul(a, b, '11B')
    print("a*b =", d)
    e = bytes(input("e:"), encoding='utf-8')
    f = bytes(input("f:"), encoding='utf-8')
    # e = b'\xee\xac\x10\xae'
    # f = b'\xa5\x20\x0c\x0d'
    print("e=", e, "f=", f)
    h = poly_mul(e, f)
    print("e*f:", h)


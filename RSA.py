#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 11/17/2018 22:20
# @Author  : YLD10
# @Email   : yl1315348050@yahoo.com
# @File    : RSA.py
# @Software: PyCharm

"""
1. 找出质数 p 和 q
2. n = p * q
3. ψ(n) = (p-1) * (q-1) 欧拉函数
4. 公钥：e  1<e<ψ(n) 的整数，与 ψ(n) 互质
5. 私钥：d  e*d 除以 ψ(n) 余数为 1
6. 加密：消息密文 c = m^e % n
7. 解密：消息明文 m = c^d % n
"""
import hashlib
import math
from prime import isprime


def isrelativelyprime(a, b):
    """
    判断两个数是否互质
    :param a:
    :param b:
    :return: 互质返回 True 否则返回 False
    """
    # 不是正整数谈不上互质
    if a <= 0 or b <= 0:
        return False
    # 1 与任何正整数都互质
    if 1 == a or 1 == b:
        return True
    # a 与 b 都不为 0 情况下相等就不可能互质
    if a == b:
        return False
    # 两个连续的自然数一定是互质数
    if abs(a - b) == 1:
        return True
    # 两个连续的奇数一定是互质数
    if a & 1 == 1 and b & 1 == 1 and abs(a - b) == 2:
        return True
    # 根据最大公约数是否为 1 判断互质
    while True:
        t = a % b
        if 0 == t:
            break
        else:
            a = b
            b = t
    if b > 1:
        return False
    return True


def ex_gcd(a, b):
    """
        扩展欧几里得算法
        :param a:
        :param b:
        :return: ans, x, y = 最大公约数，一组解 (x, y)
        """
    result = [1, 0]

    def ex_gcd_inter(a_l, b_l, result_l):
        if 0 == b_l:
            return a_l
        ans = ex_gcd_inter(b_l, a_l % b_l, result_l)
        result_l[0], result_l[1] = result_l[1], result_l[0] - (a_l // b_l) * result_l[1]
        return ans

    return ex_gcd_inter(a, b, result), result[0], result[1]


def get_e(fn_l):
    """
    获取公钥 e
    :param fn_l: ψ(n) 欧拉函数值
    :return: 密钥
    """
    if not isinstance(fn_l, int):
        raise ValueError("ψ(n) 必须是整数")
    if fn_l < 3:
        raise ValueError("ψ(n) 必须是大于 2 的正整数")

    for i in range(100, fn_l):
        if isrelativelyprime(i, fn_l):
            return i
    for i in range(2, 100):
        if isrelativelyprime(i, fn_l):
            return i

    raise RuntimeError("发生未知的错误")


def get_d(e_l, fn_l):
    """
    计算私钥 d
    :param e_l: 公钥
    :param fn_l: ψ(n) 欧拉函数值
    :return: 公钥
    """
    gcd, x, y = ex_gcd(e_l, fn_l)
    if 1 % gcd != 0:
        return -1
    x *= 1 // gcd
    fn_l /= gcd
    fn_l = abs(fn_l)
    x %= fn_l
    if x <= 0:
        x += fn_l
    return int(x)


def string2bin(str_l):
    """
      文本字符串转二进制字符串
      :param str_l:
      :return: 二进制格式的字符串
    """
    str_l = str(str_l)
    bin_str = ""
    for b in bytes(str_l, encoding="UTF-8"):
        bin_str += bin(int(b))[2:].zfill(8)

    return bin_str


def bin2string(bin_str):
    """
      二进制字符串转文本字符串
      :param bin_str:
      :return: 文本字符串
    """
    bin_str = str(bin_str)
    bin_len = len(bin_str)
    re_bytes = bytearray()
    for b in range(0, bin_len, 8):
        left = b
        right = b + 8
        re_bytes.append(int(bin_str[left:right], 2))

    return re_bytes.decode(encoding="UTF-8")


def encrypt(m_l, e_l, n_l):
    """
    分段加密消息，返回拼接后的密文
    :param m_l: 消息明文
    :param e_l: 公钥
    :param n_l: n = p * q
    :return: 加密后拼接而成的 16 进制格式密文
    """

    def encrypt_inter(m_l_l, e_l_l, n_l_l):
        """
        加密消息段的整数值，返回密文 c
        :param m_l_l: 消息明文
        :param e_l_l: 公钥
        :param n_l_l: n = p * q
        :return: 消息密文 c = m^e % n
        """
        if not isinstance(m_l_l, int) or not isinstance(e_l_l, int) or not isinstance(n_l_l, int):
            raise ValueError("消息明文，公钥和 n 都必须是整型数据")
        return (m_l_l ** e_l_l) % n_l_l

    bin_n = bin(n_l)[2:]
    n_len = len(bin_n)
    bin_m = string2bin(m_l)
    bin_m_len = len(bin_m)

    left = 0
    right = n_len - 1 if n_len < bin_m_len else bin_m_len - 1

    bin_enc = bin(encrypt_inter(int(bin_m[left:right], 2), e_l, n_l))[2:].zfill(n_len)
    for i in range(right, bin_m_len, n_len - 1):
        left = right
        right = i + n_len - 1
        bin_enc += bin(encrypt_inter(int(bin_m[left:right], 2), e_l, n_l))[2:].zfill(n_len)

    return hex(int(bin_enc, 2))[2:]


def decrypt(c_l, d_l, n_l):
    """
    分段解密消息，返回拼接后的明文
    :param c_l: 消息密文
    :param d_l: 私钥
    :param n_l: n = p * q
    :return: 解密后拼接而成的明文
    """

    def decrypt_inter(c_l_l, d_l_l, n_l_l):
        """
        解密消息段的整数值，返回明文 m
        :param c_l_l: 消息密文
        :param d_l_l: 私钥
        :param n_l_l: n = p * q
        :return: 消息明文 m = c^d % n
        """
        if not isinstance(c_l_l, int) or not isinstance(d_l_l, int) or not isinstance(n_l_l, int):
            raise ValueError("消息密文，私钥和 n 都必须是整型数据")
        return (c_l_l ** d_l_l) % n_l_l

    bin_n = bin(n_l)[2:]
    n_len = len(bin_n)
    bin_c = bin(int(c_l, 16))[2:]
    bin_c = bin_c.zfill(math.ceil(len(bin_c) / n_len) * n_len)
    c_len = len(bin_c)
    left = 0
    right = n_len

    bin_dec = bin(decrypt_inter(int(bin_c[left:right], 2), d_l, n_l))[2:].zfill(n_len - 1)
    for i in range(right, c_len, n_len):
        left = right
        right = i + n_len
        if right == c_len:
            tmp_bin = bin(decrypt_inter(int(bin_c[left:right], 2), d_l, n_l))[2:]
            need_size = (len(bin_dec) + len(tmp_bin)) % 8
            if 0 == need_size:
                bin_dec += tmp_bin
            else:
                bin_dec += tmp_bin.zfill((8 - need_size) + len(tmp_bin))
        else:
            bin_dec += bin(decrypt_inter(int(bin_c[left:right], 2), d_l, n_l))[2:].zfill(n_len - 1)

    return bin2string(bin_dec)


if __name__ == '__main__':
    p = 53
    q = 61

    if isprime(p) and isprime(q):
        print("p 和 q 均为素数")
        n = p * q
        fn = (p - 1) * (q - 1)
        e = get_e(fn)
        d = get_d(e, fn)
        m = "中文"
        print("n: %d, fn: %d, e: %d, d: %d" % (n, fn, e, d))

        mess_digest = hashlib.md5(bytes(str(m), encoding="UTF-8")).hexdigest()
        print("begin encrypt")
        enc_digest = encrypt(mess_digest, e, n)
        print("end encrypt")
        print("begin decrypt")
        recv_digest = decrypt(enc_digest, d, n)
        print("end decrypt")

        if mess_digest == recv_digest:
            print("签名成功")
            print("message: %s" % m)
        else:
            print("签名失败")
    else:
        print("p 或 q 为非素数")

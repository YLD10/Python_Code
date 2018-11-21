#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 11/20/2018 23:08
# @Author  : YLD10
# @Email   : yl1315348050@yahoo.com
# @File    : DES.py
# @Software: PyCharm
"""
              64 位明文                                                      64 位密钥
                 |                                                              |
           进行初始置换（In: 64 Out: 64）                                   进行密钥置换（In: 64 Out: 56）
16 轮            |                                               16 轮          |
———————>得到 64 位待加工密文                                       ——————> 得到 56 位密钥 <—————
|         /            \                                         |        /          \      |
|   左 32 位          右 32 位                                    |   左 28 位      右 28 位  |
|       |                |                                       |      |            |      |
|       |             扩展置换（In: 32 Out: 48）                  ————循环左移      循环左移————
|       |                |                                                \        /
|       |          与子密钥 Ki 异或（In: 48 Out: 48）<———                  压缩置换（In: 56 Out: 48）
|       |                |                             |                      |
|       |             S 盒压缩（In: 48 Out: 32）        ——————————————得到 K1,K2,K3,...K16
|       |                |
|       |              P 置换（In: 32 Out: 32）
|       |                |
|       |————————>与左 32 位异或（In: 32 Out: 32）
|       |                |
|  被上面的初始    成为下一轮的右 32 位
| 右 32 位所替换          |
|       |                |
——————————————————————————
                | 16 轮迭代完成后
             末置换
                |
    经 DES 加密后的 64 位密文
"""
from RSA import string2bin, bin2string

subkeys = None


def init_displace(bin_str):
    """
    初始置换（IP 置换）
    :param bin_str: 64 位明文
    :return: 置换后的 64 位密文
    """
    if len(bin_str) != 64:
        raise ValueError("二进制字符串长度必须是 64")
    displace_table = [58, 50, 42, 34, 26, 18, 10, 2,
                      60, 52, 44, 36, 28, 20, 12, 4,
                      62, 54, 46, 38, 30, 22, 14, 6,
                      64, 56, 48, 40, 32, 24, 16, 8,
                      57, 49, 41, 33, 25, 17, 9, 1,
                      59, 51, 43, 35, 27, 19, 11, 3,
                      61, 53, 45, 37, 29, 21, 13, 5,
                      63, 55, 47, 39, 31, 23, 15, 7]
    re_bin = ""
    for i in displace_table:
        re_bin += bin_str[i - 1]

    return re_bin


def key_displace(key_bin):
    """
    密钥置换
    :param key_bin: 64 位密钥
    :return: 置换后的 56 位密钥
    """
    if len(key_bin) != 64:
        raise ValueError("二进制密钥字符串长度必须是 64")
    key_table = [57, 49, 41, 33, 25, 17, 9,
                 1, 58, 50, 42, 34, 26, 18,
                 10, 2, 59, 51, 43, 35, 27,
                 19, 11, 3, 60, 52, 44, 36,
                 63, 55, 47, 39, 31, 23, 15,
                 7, 62, 54, 46, 38, 30, 22,
                 14, 6, 61, 53, 45, 37, 29,
                 21, 13, 5, 28, 20, 12, 4]

    key_bin_56 = ""
    for i in key_table:
        key_bin_56 += key_bin[i - 1]

    return key_bin_56


def get_subkey(key_bin_56, rotate_time):
    """
    获取 48 位的子密钥
    :param key_bin_56: 上一轮迭代产生的 56 位密钥
    :param rotate_time: 要获取的是第几轮迭代的子密钥
    :return: 48 位长的子密钥
    """
    if len(key_bin_56) != 56:
        raise ValueError("二进制密钥字符串长度必须是 56")
    rotate_table = [1, 1, 2, 2, 2, 2, 2, 2,
                    1, 2, 2, 2, 2, 2, 2, 1]

    displace_table = [14, 17, 11, 24, 1, 5,
                      3, 28, 15, 6, 21, 10,
                      23, 19, 12, 4, 26, 8,
                      16, 7, 27, 20, 13, 2,
                      41, 52, 31, 37, 47, 55,
                      30, 40, 51, 45, 33, 48,
                      44, 49, 39, 56, 34, 53,
                      46, 42, 50, 36, 29, 32]

    left_key_bin_56 = key_bin_56[:28]
    right_key_bin_56 = key_bin_56[28:]
    for i in range(rotate_table[rotate_time]):
        left_key_bin_56 = left_key_bin_56[28:] + left_key_bin_56[:28]
        right_key_bin_56 = right_key_bin_56[28:] + right_key_bin_56[:28]

    key_bin_48 = ""
    for i in displace_table:
        key_bin_48 += key_bin_56[i - 1]

    return key_bin_56, key_bin_48


def init_subkeys(key_bin):
    subkeys_list = []
    key_bin_56 = key_displace(key_bin)
    for i in range(16):
        key_bin_56, key_bin_48 = get_subkey(key_bin_56, i)
        subkeys_list.append(key_bin_48)

    return subkeys_list


def extend_displace(bin_str):
    """
    扩展置换（E 盒置换）
    :param bin_str: 32 位密文
    :return: 置换后的 32 位密文
    """
    if len(bin_str) != 32:
        raise ValueError("二进制字符串长度必须是 32")
    displace_table = [2, 1, 2, 3, 4, 5,
                      4, 5, 6, 7, 8, 9,
                      8, 9, 10, 11, 12, 13,
                      12, 13, 14, 15, 16, 17,
                      16, 17, 18, 19, 20, 21,
                      20, 21, 22, 23, 24, 25,
                      24, 25, 26, 27, 28, 29,
                      28, 29, 30, 31, 32, 1]
    re_bin = ""
    for i in displace_table:
        re_bin += bin_str[i - 1]

    return re_bin


def sbox_displace(bin_str):
    """
    S 盒置换
    :param bin_str: 48 位的密文
    :return: 压缩后的 32 位密文
    """
    if len(bin_str) != 48:
        raise ValueError("二进制字符串长度必须是 48")
    sbox1 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
             0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
             4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
             15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    sbox2 = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
             3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
             0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
             13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    sbox3 = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
             13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
             13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
             1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    sbox4 = [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
             13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
             10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
             3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    sbox5 = [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
             14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
             4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
             11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    sbox6 = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
             10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
             9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
             4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    sbox7 = [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
             13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
             1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
             6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    sbox8 = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
             1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
             7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
             2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]

    sboxs = [sbox1, sbox2, sbox3, sbox4, sbox5, sbox6, sbox7, sbox8]

    re_bin = ""
    left = 0
    right = 6
    for box in sboxs:
        row = int(bin_str[left] + bin_str[right - 1], 2)
        col = int(bin_str[left + 1:right - 1], 2)
        re_bin += bin(box[row * 16 + col])[2:].zfill(4)
        left = right
        right += 6

    return re_bin


def p_displace(bin_str):
    """
    P 置换
    :param bin_str: 32 位的密文
    :return: 置换后的 32 位密文
    """
    if len(bin_str) != 32:
        raise ValueError("二进制字符串长度必须是 32")
    displace_table = [16, 7, 20, 21, 29, 12, 28, 17,
                      1, 15, 23, 26, 5, 18, 31, 10,
                      2, 8, 24, 14, 32, 27, 3, 9,
                      19, 13, 30, 6, 22, 11, 4, 25]
    re_bin = ""
    for i in displace_table:
        re_bin += bin_str[i - 1]

    return re_bin


def final_displace(bin_str):
    """
    末置换（逆 IP 置换）
    :param bin_str: 64 位密文
    :return:置换后的 64 位密文
    """
    if len(bin_str) != 64:
        raise ValueError("二进制字符串长度必须是 64")
    displace_table = [40, 8, 48, 16, 56, 24, 64, 32,
                      39, 7, 47, 15, 55, 23, 63, 31,
                      38, 6, 46, 14, 54, 22, 62, 30,
                      37, 5, 45, 13, 53, 21, 61, 29,
                      36, 4, 44, 12, 52, 20, 60, 28,
                      35, 3, 43, 11, 51, 19, 59, 27,
                      34, 2, 42, 10, 50, 18, 58, 26,
                      33, 1, 41, 9, 49, 17, 57, 25]
    re_bin = ""
    for i in displace_table:
        re_bin += bin_str[i - 1]

    return re_bin


def padding(bin_str):
    """
       明文填充至 64 的整数倍长度
       :param bin_str: 消息的二进制明文字符串
       :return: 填充后的二进制字符串
       """
    padding_str = "0111111111111111111111111111111111111111111111111111111111111111"
    r = len(bin_str) % 64
    if 0 == r:
        bin_str += padding_str
    else:
        bin_str += padding_str[:64 - r]

    return bin_str


def unpadding(bin_str):
    """
    去除填充
    :param bin_str: 填充后的明文二进制串
    :return: 没有填充的二进制明文串
    """
    return bin_str[:bin_str.rfind("0")]


def encrypt_round(bin_str, subkeys_list):
    """
    进行 16 次迭代运算加密
    :param bin_str: 64 位加工密文
    :param subkeys_list: 包含 16 个 48 位子密钥的列表
    :return: 迭代加密后的 64 位密文
    """
    if len(bin_str) != 64:
        raise ValueError("二进制字符串的长度都必须是 64")
    left_bin_str = bin_str[:32]
    right_bin_str = bin_str[32:]

    for i in range(16):
        # 对本轮迭代的初始右部 32 位密文副本进行扩展置换
        right_bin_list_extend_48 = list(extend_displace(right_bin_str))
        # 取出当前需要的子密钥
        key_bin_48 = subkeys_list[i]
        # 经过扩展置换后的 48 密文与子密钥进行异或
        for j in range(48):
            if right_bin_list_extend_48[j] != key_bin_48[j]:
                right_bin_list_extend_48[j] = "1"
            else:
                right_bin_list_extend_48[j] = "0"

        # 异或后的 48 位密文进行 S 盒置换和 P 置换
        right_bin_list_p_32 = list(p_displace(sbox_displace("".join(right_bin_list_extend_48))))
        # 经过 P 置换后的 32 位密文与本轮迭代的初始左部 32 位密文进行异或
        for j in range(32):
            if right_bin_list_p_32[j] != left_bin_str[j]:
                right_bin_list_p_32[j] = "1"
            else:
                right_bin_list_p_32[j] = "0"

        # 本轮的初始右部 32 位密文成为下一轮的初始左部密文，
        # 经上述一轮运算后的 32 位密文成为下一轮的初始右部密文
        left_bin_str = right_bin_str
        right_bin_str = "".join(right_bin_list_p_32)

    return left_bin_str + right_bin_str


def decrypt_round(bin_str, subkeys_list):
    """
    进行 16 次迭代运算解密
    :param bin_str: 64 位加工密文
    :param subkeys_list: 包含 16 个 48 位子密钥的列表
    :return: 迭代解密后的 64 位准明文
    """
    if len(bin_str) != 64:
        raise ValueError("二进制字符串的长度都必须是 64")
    left_bin_str = bin_str[:32]
    right_bin_str = bin_str[32:]

    for i in range(16):
        # 对本轮迭代的初始左部 32 位密文副本进行扩展置换
        left_bin_list_extend_48 = list(extend_displace(left_bin_str))
        # 取出当前需要的子密钥
        key_bin_48 = subkeys_list[16 - i - 1]
        # 经过扩展置换后的 48 密文与子密钥进行异或
        for j in range(48):
            if left_bin_list_extend_48[j] != key_bin_48[j]:
                left_bin_list_extend_48[j] = "1"
            else:
                left_bin_list_extend_48[j] = "0"

        # 异或后的 48 位密文进行 S 盒置换和 P 置换
        left_bin_list_p_32 = list(p_displace(sbox_displace("".join(left_bin_list_extend_48))))
        # 经过 P 置换后的 32 位密文与本轮迭代的初始右部 32 位密文进行异或
        for j in range(32):
            if left_bin_list_p_32[j] != right_bin_str[j]:
                left_bin_list_p_32[j] = "1"
            else:
                left_bin_list_p_32[j] = "0"

        # 本轮的初始左部 32 位密文成为下一轮的初始右部密文，
        # 经上述一轮运算后的 32 位密文成为下一轮的初始左部密文
        right_bin_str = left_bin_str
        left_bin_str = "".join(left_bin_list_p_32)

    return left_bin_str + right_bin_str


def encrypt(enc_str, key_str):
    """
    DES 加密主函数
    :param enc_str: 待加密的二进制串
    :param key_str: 密钥文本字符串
    :return: 加密后的 16 进制格式字符串
    """
    global subkeys
    # 若子密钥还未生成，先生成 16 个 48 位的子密钥
    if subkeys is None:
        subkeys = init_subkeys(string2bin(key_str))

    # 对待加密串进行 64 位填充
    enc_bin = padding(string2bin(str(enc_str)))
    re_bin = ""

    left = 0
    right = 64
    for_time = len(enc_bin) // 64
    # 分段加密
    for i in range(for_time):
        bin_str = enc_bin[left:right]
        # 对本段二进制明文串进行 DES 加密
        re_bin += final_displace(encrypt_round(init_displace(bin_str), subkeys))
        left = right
        right += 64

    return bin2hexstring(re_bin)


def decrypt(dec_str, key_str):
    """
    DES 解密主函数
    :param dec_str: 待解密的 16 进制字符串
    :param key_str: 密钥文本字符串
    :return: 解密后的明文文本字符串
    """
    global subkeys
    # 若子密钥还未生成，先生成 16 个 48 位的子密钥
    if subkeys is None:
        subkeys = init_subkeys(string2bin(key_str))

    # 16 进制串转 2 进制串
    dec_bin = hex2binstring(dec_str)
    re_bin = ""

    left = 0
    right = 64
    for_time = len(dec_bin) // 64
    # 分段解密
    for i in range(for_time):
        bin_str = dec_bin[left:right]
        # 对本段二进制密文串进行 DES 解密
        re_bin += final_displace(decrypt_round(init_displace(bin_str), subkeys))
        left = right
        right += 64

    return bin2string(unpadding(re_bin))


def bin2hexstring(bin_str):
    """
    二进制串转十六进制串，按照 4：1 比例转换
    :param bin_str: 二进制串
    :return: 十六进制串
    """
    bin_len = len(bin_str)
    left = 0
    right = 4
    re_str = hex(int(bin_str[left:right], 2))[2:]
    for i in range(right, bin_len, 4):
        left = right
        right += 4
        re_str += hex(int(bin_str[left:right], 2))[2:]

    return re_str


def hex2binstring(hex_str):
    """
    十六进制串转二进制串，按照 1：4 比例转换
    :param hex_str: 十六进制串
    :return: 二进制串
    """
    re_str = ""
    for h in hex_str:
        re_str += bin(int(h, 16))[2:].zfill(4)

    return re_str


if __name__ == '__main__':
    message = "世界你好"
    key = "12345678"  # 按 UTF-8 编码转即为 64 位

    c = encrypt(message, key)
    print("密文：%s" % c)
    m = decrypt(c, key)
    print("明文：%s" % m)

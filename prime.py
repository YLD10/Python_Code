#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 11/19/2018 23:40
# @Author  : YLD10
# @Email   : yl1315348050@yahoo.com
# @File    : prime.py
# @Software: PyCharm
import math


def isprime(num):
    """
    判断给定的 num 是不是一个素数
    :param num:
    :return: 是素数返回 True 否则返回 False
    """
    # 如果不是整型数据则不可能是素数
    if not isinstance(num, int):
        return False
    # 筛掉小于 2 的数
    if num < 2:
        return False
    # 筛掉 2 和 3
    if 2 == num or 3 == num:
        return True
    # 筛掉偶数
    if num & 1 == 0:
        return False
    # 筛掉 3 的倍数
    if num % 3 == 0:
        return False

    sqrtn = int(math.floor(num ** 0.5))
    # 需要判断 5 以及 大于 5 的数中处于 6 的倍数前后的两个数
    for i in range(5, sqrtn + 1, 6):
        if num % i == 0:
            return False
    for i in range(7, sqrtn + 1, 6):
        if num % i == 0:
            return False

    return True


if __name__ == '__main__':
    pass

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 4/6/2018 9:16
# @Author  : YLD10
# @Email   : yl1315348050@yahoo.com
# @File    : no_zero_num_first.py
# @Software: PyCharm


def split_by_blank_int(arr_l):
    arr_l = arr_l.split(' ')
    try:
        arr_l = [i_l for i_l in arr_l if i_l != '']
        arr_l = [int(i_l) for i_l in arr_l]
    except ValueError:
        print('有非法符号！')
        return []
    return arr_l


def deal(arr_l):
    i_l = 0
    j_l = 0
    for i_l in range(len(arr_l)):
        if arr_l[i_l] != 0:
            arr_l[j_l] = arr_l[i_l]
            j_l += 1
    for i_l in range(j_l, len(arr_l)):
        arr_l[i_l] = 0

    return arr_l


if __name__ == '__main__':
    arr = input()
    arr = split_by_blank_int(arr)
    arr = deal(arr)
    print(arr)

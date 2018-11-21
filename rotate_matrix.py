#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 4/6/2018 9:57
# @Author  : YLD10
# @Email   : yl1315348050@yahoo.com
# @File    : rotate_matrix.py
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


if __name__ == '__main__':
    matrix = []
    tmp = input()
    tmp = tmp.split('\n')
    for line in tmp:
        line = split_by_blank_int(line)
        matrix.append(line)

    print(matrix)

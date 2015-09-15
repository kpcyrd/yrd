#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2015, PyroPeter <pyropeter@pyropeter.eu>
# Copyright (c) 2014-2015, Finn <thefinn93@thefinn93.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Stolen from https://gist.github.com/pyropeter/642505

"""Bencode library, for bencoding and bdecoding python objects"""

import collections


def bencode(obj):
    """Bencodes obj and returns it as a string"""
    if isinstance(obj, int):
        return "i" + str(obj) + "e"

    if isinstance(obj, str):
        if not obj:
            return None
        return str(len(obj)) + ":" + obj

    if isinstance(obj, list):
        res = "l"
        for elem in obj:
            elem = bencode(elem)
            if elem:
                res += elem
        return res + "e"

    if isinstance(obj, dict):
        res = "d"
        for key in sorted(obj.keys()):
            if key in obj:
                value = bencode(obj[key])
                key = bencode(key)
                if key and value:
                    res += key + value

        return res + "e"

    if isinstance(obj, unicode):
        return bencode(obj.encode('utf-8'))

    if isinstance(obj, collections.OrderedDict):
        return bencode(dict(obj))
    raise Exception("Unknown object: %s (%s)" % (repr(obj), repr(type(obj))))


def bdecode(text):
    """Decodes a bencoded bytearray and returns it as a python object"""
    text = text.decode('utf-8')

    def bdecode_next(start):
        """bdecode helper function"""
        if text[start] == 'i':
            end = text.find('e', start)
            return int(text[start+1:end], 10), end + 1

        if text[start] == 'l':
            res = []
            start += 1
            while text[start] != 'e':
                elem, start = bdecode_next(start)
                res.append(elem)
            return res, start + 1

        if text[start] == 'd':
            res = {}
            start += 1
            while text[start] != 'e':
                key, start = bdecode_next(start)
                value, start = bdecode_next(start)
                res[key] = value
            return res, start + 1

        lenend = text.find(':', start)
        length = int(text[start:lenend], 10)
        end = lenend + length + 1
        return text[lenend+1:end], end
    return bdecode_next(0)[0]

# vim: set ts=4 sw=4 et:

#!/usr/bin/python3.6
#coding: utf-8

from neverland.utils import ObjectifiedDict


def test_convert():
    od = ObjectifiedDict()

    d2convert = {
        'a': 1,
        'b': {
            'c': [2, {'x': 3}],
            'd': (4, 5),
            'e': {6, 7},
        }
    }
    r = od.__convert__(d2convert)
    assert isinstance(r, ObjectifiedDict)
    assert isinstance(r.b, ObjectifiedDict)
    assert isinstance(r.b.c, list)
    assert isinstance(r.b.c[1], ObjectifiedDict)
    assert isinstance(r.b.d, tuple)
    assert isinstance(r.b.e, set)
    assert r.a == 1
    assert r.b.c[0] == 2
    assert r.b.c[1].x == 3
    assert r.b.d[0] == 4 and r.b.d[1] == 5
    assert 6 in r.b.e and 7 in r.b.e

    d2convert = [1, {'a': 2}]
    r = od.__convert__(d2convert)
    assert isinstance(r, list)
    assert isinstance(r[1], ObjectifiedDict)
    assert r[0] == 1
    assert r[1].a == 2

    d2convert = (1, {'a': 2})
    r = od.__convert__(d2convert)
    assert isinstance(r, tuple)
    assert isinstance(r[1], ObjectifiedDict)
    assert r[0] == 1
    assert r[1].a == 2


def test_update():
    od = ObjectifiedDict()

    d2update = {
        'a': {
            'a1': 1,
            'a2': 'string',
        },
        'b': [1, 2, {'b1': 3}],
        'c': (4, 5, {'c1': 6}),
        'd': {7, 8},
        'e': 'STRING!',
    }
    od.__update__(**d2update)

    container = object.__getattribute__(od, '__container__')
    assert isinstance(container, dict)
    assert isinstance(container['a'], ObjectifiedDict)
    assert isinstance(container['b'], list)
    assert isinstance(container['b'][2], ObjectifiedDict)
    assert isinstance(container['c'], tuple)
    assert isinstance(container['c'][2], ObjectifiedDict)
    assert isinstance(container['d'], set)
    assert isinstance(container['e'], str)

    assert container['a'].a1 == 1
    assert container['a'].a2 == 'string'
    assert container['b'][0] == 1
    assert container['b'][1] == 2
    assert container['b'][2].b1 == 3
    assert container['c'][0] == 4
    assert container['c'][1] == 5
    assert container['c'][2].c1 == 6
    assert 7 in container['d'] and 8 in container['d']
    assert container['e'] == 'STRING!'


def test_iter():
    od = ObjectifiedDict(
        a={'a1': 1, 'a2': 2},
        b={'b1': 3, 'b2': 4},
    )

    for k, v in od:
        if k == 'a':
            for ka, va in v:
                if ka == 'a1':
                    assert va == 1
                if ka == 'a2':
                    assert va == 2
        elif k == 'b':
            for kb, vb in v:
                if kb == 'b1':
                    assert vb == 3
                if kb == 'b2':
                    assert vb == 4


def test_bool():
    od_ture = ObjectifiedDict(a=1)
    od_false = ObjectifiedDict()

    assert bool(od_ture) is True
    assert bool(od_false) is False


def test_to_dict():
    data = {
        'a': {'a1': 1, 'a2': 2},
        'b': [1, 1.2, {'b1': 3, 'b2': 4}],
        'c': (1, 2, 3),
        'd': {4, 5, 6},
        'e': '!@#$%^',
    }
    od = ObjectifiedDict(**data)
    exported = od.__to_dict__()

    assert exported != data
    assert exported['a'] == data['a']
    assert exported['b'] == data['b']
    assert exported['c'] == list(data['c'])
    assert exported['d'] == list(data['d'])
    assert exported['e'] == data['e']

#!/usr/bin/python3.7
#coding: utf-8

import os


ATF_DIR = 'atf'


def find_libpath():
    libdir = None
    cwd = os.getcwd()
    build_dir = os.path.join(cwd, 'build')

    for fn in os.listdir(build_dir):
        if fn.startswith('lib.'):
            libdir = fn
            break

    return os.path.join(build_dir, libdir)


def mkatfdir():
    try:
        os.makedirs(ATF_DIR)
    except FileExistsError:
        pass


def main():
    libpath = find_libpath()
    nvld_dir = os.path.join(libpath, 'nvld')

    mkatfdir()
    os.system(f'cp -r {nvld_dir} {ATF_DIR}')
    os.system(f'cp nl.py {ATF_DIR}')


if __name__ == '__main__':
    main()

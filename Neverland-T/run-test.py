#!/usr/bin/python3.7
#coding: utf-8

import re
import os
import sys 

from pytest import main as pytest_main


def find_libpath():
    libdir = None
    cwd = os.getcwd()
    build_dir = os.path.join(cwd, 'build')

    for fn in os.listdir(build_dir):
        if fn.startswith('lib.'):
            libdir = fn
            break

    return os.path.join(build_dir, libdir)


if __name__ == '__main__':
    libpath = find_libpath()
    sys.path.append(libpath)

    sys.argv.append("-s")
    sys.argv.append("tests")
    sys.exit(pytest_main())

#!/usr/bin/python3.6
#coding: utf-8

import re
import os
import sys 

from pytest import main as pytest_main

if __name__ == '__main__':
    sys.path.append(os.getcwd())

    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.argv.append("tests")
    sys.exit(pytest_main())

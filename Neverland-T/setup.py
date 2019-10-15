#!/usr/bin/python3.7

from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize


extensions = [
    Extension('neverland/**', ['neverland/**/*.pyx']),
]


setup(
    ext_modules = cythonize(extensions)
)

#!/usr/bin/python3.7

from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize


extensions = [
    Extension(
        'nvld/**',
        ['nvld/**/*.pyx'],
        libraries=['crypto'],
    ),
]


setup(
    ext_modules=cythonize(
        extensions,
        compiler_directives={'language_level': 3},
    )
)

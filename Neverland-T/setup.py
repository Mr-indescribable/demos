#!/usr/bin/python3.7

import os

from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize


from distutils.command.build_ext import build_ext


# gets an extension file name without the PEP-3149 version identifier
def get_a_short_ext_filename(self, ext_name):
    from distutils.sysconfig import get_config_var
    ext_path = ext_name.split('.')
    ext_suffix = '.so'
    return os.path.join(*ext_path) + ext_suffix


# I hack you XD
build_ext.get_ext_filename = get_a_short_ext_filename


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

'''
Unapologetically adapted from Jeff Knupp's execellent article:

http://www.jeffknupp.com/blog/2013/08/16/open-sourcing-a-python-project-the-right-way/
'''
from __future__ import print_function
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import io
import codecs
import os
import sys

import keybase

here = os.path.abspath(os.path.dirname(__file__))

def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        with io.open(filename, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)

long_description = '''The ``keybase`` python API allows you to search, download
and use the stored keys in the Keybase directory. You can do things like encrypt
messages and files for a user or verify a signature on a file from a user.
Eventually it will be extended to allow you to administer Keybase user
identities and their associated public/private keypairs via the ``KeybaseAdmin`` class.

The official documentation for the project can be found here: http://keybase-python-api.readthedocs.org/en/latest/

The source code for the project can be found here: https://github.com/ianchesal/keybase-python
'''

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errcode = pytest.main(self.test_args)
        sys.exit(errcode)

class Tox(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import tox
        errcode = tox.cmdline(self.test_args)
        sys.exit(errcode)

setup(
    name = 'keybase-api',
    version = keybase.__version__,
    url = 'https://github.com/ianchesal/keybase-python',
    license = 'Apache Software License, v2.0',
    author = 'Ian Chesal',
    tests_require = ['tox'],
    install_requires = [
        'astroid>=1.0.1',
        'cffi>=0.8.2',
        'cov-core>=1.7',
        'coverage>=3.7.1',
        'docutils>=0.11',
        'gnupg>=1.2.5',
        'Jinja2>=2.7.2',
        'logilab-common>=0.61.0',
        'MarkupSafe>=0.19',
        'mock>=1.0.1',
        'py>=1.4.20',
        'pycparser>=2.10',
        'Pygments>=1.6',
        'pylint>=1.1.0',
        'pytest-cov>=1.6',
        'pytest>=2.5.2',
        'requests>=2.2.1',
        'Sphinx>=1.2.2',
        'sphinx_rtd_theme>=0.1.6',
        'tox>=1.7.1',
        'virtualenv>=1.11.4',
        'wsgiref>=0.1.2',
    ],
    cmdclass = {'test': Tox},
    author_email = 'ian.chesal@gmail.com',
    description = 'A Python implementation of the keybase.io API',
    long_description = long_description,
    packages = ['keybase'],
    include_package_data = True,
    platforms = 'any',
    test_suite = 'keybase.test.test_keybase',
    classifiers = [
        'Programming Language :: Python',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        ],
    extras_require = {
        'testing': ['pytest'],
    }
)
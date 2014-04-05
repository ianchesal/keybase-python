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

#long_description = read('README.txt', 'CHANGES.txt')
long_description = 'Test'

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
    name = 'keybase',
    version = keybase.__version__,
    url = 'https://github.com/ianchesal/keybase-python',
    license = 'Apache Software License, v2.0',
    author = 'Ian Chesal',
    tests_require = ['tox'],
    install_requires = [
        'Jinja2>=2.7.2',
        'MarkupSafe>=0.19',
        'Pygments>=1.6',
        'Sphinx>=1.2.2',
        'cov-core>=1.7',
        'coverage>=3.7.1',
        'docutils>=0.11',
        'mock>=1.0.1',
        'py>=1.4.20',
        'pytest>=2.5.2',
        'pytest-cov>=1.6',
        'tox>=1.7.1',
        'virtualenv>=1.11.4',
        'wsgiref>=0.1.2'
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
        'Natural Language :: English',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        ],
    extras_require = {
        'testing': ['pytest'],
    }
)
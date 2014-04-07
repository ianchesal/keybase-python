'''
Regression type tests for the Keybase APIs

These perform comparisons against golden file patterns to ensure that tests
are passing and not failing.
'''

import os
import pytest
from keybase.keybase import Keybase

def compare_string_to_file(somestring, somefile):
    '''
    Loads the contents of somefile in to a str variable and asserts that
    it's equal to whatever somestring points to.

    This should only be used for really small comparisons. For big 
    comparisons you want to use:

        compare_stream_to_file(somestream, somefile)

    Which does a line-by-line comparison of two streams without having
    to load all the content in to memory before hand.

    The somefile name should be just the name of the file. The function
    will look up the file in the appropriate golden results location
    for you.

    Returns True if the string matches the file contents. Returns False
    if they do not match.
    '''
    is_equal = False
    golden_file = os.path.join(os.getcwd(), 'test', 'golden', somefile)
    with open(golden_file, 'r') as gfile:
        gcontents = gfile.read()
        is_equal = gcontents == somestring
    return is_equal

def compare_files(leftfile, rightfile):
    '''
    Loads the contents of two files and compares them for absolute
    equality. Does this in an most horribly memory inefficient manner for
    now so don't use it for large file comparisons.

    Returns True if the string matches the file contents. Returns False
    if they do not match.
    '''
    is_equal = False
    with open(leftfile, 'r') as lfile:
        with open(rightfile, 'r') as rfile:
            lcontents = lfile.read()
            rcontents = rfile.read()
            is_equal = lcontents == rcontents
    return is_equal

def test_public_key_downloading():
    '''
    Test downloading the ASCII representation of someone's public key.
    It should be equal to the golden version of the public key we have
    on file for this test already.
    '''
    k = Keybase('irc')
    pkey = k.get_public_key().ascii
    assert compare_string_to_file(somestring=pkey, somefile='irc.public.key')


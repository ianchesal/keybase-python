'''
Regression type tests for the Keybase APIs

These perform comparisons against golden file patterns to ensure that tests
are passing and not failing.
'''

import os
import pytest
import tempfile
import shutil
import gnupg
import keybase


GPG_KEY_DATA = '''-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v0.1.1
Comment: https://keybase.io/crypto

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
BzQzv4OEmz434EDyNGj71cdiOGadG3z0
=8tN7
-----END PGP PUBLIC KEY BLOCK-----'''

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
    k = keybase.Keybase('irc')
    pkey = k.get_public_key().ascii
    assert compare_string_to_file(somestring=pkey, somefile='irc.public.key')

def test_public_key_gpg_integration():
    '''
    A basic test for the KeybasePublicKey() class. Makes sure it plays
    nice with the GnuPGP Python module.
    '''
    key_fingerprint = '7cc0ce678c37fc27da3ce494f56b7a6f0a32a0b9'
    initopts = {'bundle': GPG_KEY_DATA, 'key_fingerprint': key_fingerprint}
    tempdir = tempfile.mkdtemp(suffix='.keybase-test')
    gpg = gnupg.GPG(homedir=tempdir, verbose=False, use_agent=False, binary=keybase.gpg())
    import_result = gpg.import_keys(GPG_KEY_DATA)
    assert len(import_result.fingerprints) > 0
    key = keybase.KeybasePublicKey(**initopts)
    assert key.key_fingerprint == key_fingerprint
    assert import_result.fingerprints[0].lower() == key_fingerprint
    assert key.key_fingerprint == import_result.fingerprints[0].lower()
    del gpg
    shutil.rmtree(tempdir)

def test_verify_file_embedded_signature():
    '''
    Verifies the signature on an embedded, signed file. This is a file signed
    with:

        gpg -u keybase.io/irc --sign helloworld.txt

    So it's binary output and prefixed with .gpg.
    '''
    k = keybase.Keybase('irc')
    pkey = k.get_public_key()
    fname = os.path.join(os.getcwd(), 'test', 'golden', 'helloworld.txt.gpg')
    verified = pkey.verify_file(
        fname,
        throw_error=True)
    assert verified
    # Compare this to a straight-up GnuPGP verification using the
    # known public key from the pair that signed the file.
    tempdir = tempfile.mkdtemp(suffix='.keybase-test')
    gpg = gnupg.GPG(homedir=tempdir, verbose=False, use_agent=False, binary=keybase.gpg())
    gpg.import_keys(GPG_KEY_DATA)
    with open(fname, 'rb') as fdata:
        vobj = gpg.verify_file(fdata)
        assert vobj.valid
    del gpg
    shutil.rmtree(tempdir)

def test_verify_file_detached_signature():
    '''
    Verifies the signature on an embedded, signed file. This is a file signed
    with:

        gpg -u keybase.io/irc --detach-sign helloworld.txt

    So it's the data file helloworld.txt plus the detached signature file
    helloworld.txt.sig that are used together to do the verification.
    '''
    k = keybase.Keybase('irc')
    pkey = k.get_public_key()
    fname = os.path.join(os.getcwd(), 'test', 'golden', 'helloworld.txt')
    fsig = os.path.join(os.getcwd(), 'test', 'golden', 'helloworld.txt.sig')
    verified = pkey.verify_file(
        fname,
        fsig)
    assert verified
    # Compare this to a straight-up GnuPGP verification using the
    # known public key from the pair that signed the file.
    tempdir = tempfile.mkdtemp(suffix='.keybase-test')
    gpg = gnupg.GPG(homedir=tempdir, verbose=False, use_agent=False, binary=keybase.gpg())
    gpg.import_keys(GPG_KEY_DATA)
    vobj = gpg.verify_file(fname, fsig)
    assert vobj.valid
    del gpg
    shutil.rmtree(tempdir)

#import logging
#logging.basicConfig(level=logging.DEBUG)
#test_verify_file_embedded_signature()
#test_verify_file_detached_signature()
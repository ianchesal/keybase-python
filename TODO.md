* Fix long_description in setup.py, it should load from README.md
* Add a sample test to keybase/test/test_keybase.py
* Mock the results calls to the live API in the doctests embedded in the main class
* Fix the Sphinx document generation so it actually produces documents with content in it
   * For some reason the embedded Pydoc isn't being translated to the output HTML
* Finish implementing login()
* Add a KeybaseAdmin class that extends Keybase for account/key administration
* Add some methods to Keybase for encryptying, decrypting and signing things using the keys in a Keybase account
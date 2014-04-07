* Fix long_description in setup.py, it should load from README.md
* Add a sample test to keybase/test/test_keybase.py
* Mock the results calls to the live API in the doctests embedded in the main class
* Fix the Sphinx document generation so it actually produces documents with content in it
   * For some reason the embedded Pydoc isn't being translated to the output HTML
* Add a KeybaseAdmin class that extends Keybase for account/key administration
   * Class is there now, it just needs login() and admin function added
   * Finish implementing login()
* Add some methods to Keybase for encryptying, decrypting and signing things using the keys in a Keybase account
* Add more examples to [README.md](README.md) that show how to use the API to encrypt things, verify signatures on things
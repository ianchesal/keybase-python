* Fix long_description in setup.py, it should load from README.md
* Mock the results calls to the live API in the doctests embedded in the main class
* Add a KeybaseAdmin class that extends Keybase for account/key administration
   * Class is there now, it just needs login() and admin function added
   * Finish implementing login()
* Add encryption to KeybasePublicKey
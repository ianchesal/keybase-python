Core Features
-------------
* Offline support for Keybase class
   * Allow merging keys in to a persistent keystore 
   * Allow retrieving keys from persistent keystore without having to contact Keybase.io
* Seaching for Keybase.io users
   * Allow searching by user name, twitter handle, domain, email, etc.
   * Probably depends on Keybase.io UI enhancements

Long Term Features
------------------
* Add a KeybaseAdmin class that extends Keybase for account/key administration
   * Class is there now, it just needs login() and admin function added
   * Finish implementing login()

Testing
-------
* Mock the results calls to the live API in the doctests embedded in the main class

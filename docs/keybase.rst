===============
The Keybase API
===============

Keybase Common Methods
----------------------

The following common, convenience methods exist to make it easier to work with
GnuPG and the Keybase API in your code.

.. autofunction:: keybase.gpg

The ``Keybase`` Class -- Accessing Public User Data
---------------------------------------------------

The ``Keybase`` class allows you to find users in the Keybase directory and access their stored public keys. Public keys let you encrypt messages and files for a user; only the person holding the private key from the pair can decrypt a file encrypted with the public key. Public keys also let you verify the signature on data; only the user with the private key can create a signature that can be validated with the specific public key.

.. autoclass:: keybase.Keybase
    :members:
    :undoc-members:

The ``KeybasePublicKey`` Class -- Public Key Records from the Keybase.io Data Store
-----------------------------------------------------------------------------------

.. autoclass:: keybase.KeybasePublicKey
  :members:

The ``KeybaseAdmin`` Class -- Manipulating User's Public Key Data
-----------------------------------------------------------------

The ``KeybaseAdmin`` class lets you authenticate as a user to the Keybase.io public data store and manipulate the stored public keys for the user. You can add and revoke keys, create new keys and validate other user's keys.

.. note::

  This class is currently not implemented! Anything you read here is planned, not real, at this point.

.. autoclass:: keybase.KeybaseAdmin
    :members:
    :undoc-members:
    :show-inheritance:

The Keybase Error Classes
-------------------------

.. autoclass:: keybase.KeybaseError
   :members:

.. autoclass:: keybase.KeybaseUnboundInstanceError
   :members:

.. autoclass:: keybase.KeybaseUserNotFound
   :members:

.. autoclass:: keybase.KeybaseLookupInvalidError
   :members:

.. autoclass:: keybase.KeybasePublicKeyError
   :members:

.. autoclass:: keybase.KeybasePublicKeyVerifyError
   :members:

.. autoclass:: keybase.KeybasePublicKeyEncryptError
   :members:


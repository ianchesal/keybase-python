.. keybase documentation master file, created by
   sphinx-quickstart on Sat Apr  5 13:10:02 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to keybase's documentation!
===================================

What is Keybase? From `their website <https://keybase.io/>`_:

.. note::

	Keybase will be a public directory of publicly auditable public keys.
	All paired, for convenience, with unique usernames.


It provides an easy way to publish public keys, have them validated against known good sources for users like Twitter, email addresses and even web sites, and make all of this stuff discoverable. It's trying to take away the mystery of handing keys around so that cryptography can be more widely used by the masses.

The ``keybase`` python API allows you to search, download and use the stored keys in the Keybase directory. You can do things like encrypt messages and files for a user or verify a signature on a file from a user. Eventually it will be extended to allow you to administer Keybase user identities and their associated public/private keypairs via the ``KeybaseAdmin`` class.

If you're not familiar with public/private key encryption check out `this tutorial <http://computer.howstuffworks.com/encryption3.htm>`_ or Laurent Luce's excellent article `Python and cryptography with pycrypto <http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/>`_.

.. toctree::
   :maxdepth: 4

   installation
   keybase


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


========
Examples
========

Get a User's Credentials
------------------------

You can retrieve a specific user's credentials from the Keybase data store like so::

	kbase = Keybase('irc')
	primary_key = kbase.get_public_key()
	primary_key.kid
	u'0101f56ecf27564e5bec1c50250d09efe963cad3138d4dc7f4646c77f6008c1e23cf0a'

You can use the ``ascii`` or ``bundle`` properties on the ``primary_key`` object in the above example to get an ASCII version of their primary public key, suitable for feeding in to a signature verification or encryption routine. You can also use the ``primary_key`` object itself to do verification and encryption.

Verifying a Signature on String Data
------------------------------------

Where the strings are clear-signed text strings that are produced using a ``gpg`` command like so::

	gpg --clearsign helloworld.txt --local-user keybase.io/irc

These clear-signed text snippets are common in signed email. Where the body of the email is surrounded by the signature like so::

	-----BEGIN PGP SIGNED MESSAGE-----
	Hash: SHA1

	Hello, world!
	-----BEGIN PGP SIGNATURE-----
	Version: GnuPG v1

	iQEcBAEBAgAGBQJTWHSVAAoJEO7zMmcMHMCAYpEH/j2hJApaHXSj0ddgbrmUdJ2z
	vZ5DFDR9syTPHrwtRJLPH7tgdiAtUpyXLozL321JIR7sExzONl7IKdpH1Qn0y1I/
	h6mV0Dm+AAJXWtbn08rDW2WWuW4+EBEy12Cfk2r1rF8KT+g3gcc2wLejSACkf7v+
	jKo5SnvIwIMze+Msqjcz/+hbKRdEEoD2zihe6ilMfbR1tCt8GALQVa8YEoHpgkcL
	MWbXSCgM7Q0gf00kHWa3A8rClW0dzW5kJG+InbymtenaDNwoNlFb6DHUdyF//REx
	YjJ6qHf7qFwtXPBiwrZf+VYt5OnjeWW6ybYasfrJiXi1qnd6IM40QCGlR0UXhII=
	=oUn0
	-----END PGP SIGNATURE-----

These types of clear-signed strings can be verified like so::

	message_good = """
	-----BEGIN PGP SIGNED MESSAGE-----
	Hash: SHA1

	Hello, world!
	-----BEGIN PGP SIGNATURE-----
	Version: GnuPG v1

	iQEcBAEBAgAGBQJTWHSVAAoJEO7zMmcMHMCAYpEH/j2hJApaHXSj0ddgbrmUdJ2z
	vZ5DFDR9syTPHrwtRJLPH7tgdiAtUpyXLozL321JIR7sExzONl7IKdpH1Qn0y1I/
	h6mV0Dm+AAJXWtbn08rDW2WWuW4+EBEy12Cfk2r1rF8KT+g3gcc2wLejSACkf7v+
	jKo5SnvIwIMze+Msqjcz/+hbKRdEEoD2zihe6ilMfbR1tCt8GALQVa8YEoHpgkcL
	MWbXSCgM7Q0gf00kHWa3A8rClW0dzW5kJG+InbymtenaDNwoNlFb6DHUdyF//REx
	YjJ6qHf7qFwtXPBiwrZf+VYt5OnjeWW6ybYasfrJiXi1qnd6IM40QCGlR0UXhII=
	=oUn0
	-----END PGP SIGNATURE-----
	"""
	message_bad = """
	-----BEGIN PGP SIGNED MESSAGE-----
	Hash: SHA1

	Hello, another world!
	-----BEGIN PGP SIGNATURE-----
	Version: GnuPG v1

	iQEcBAEBAgAGBQJTWHSVAAoJEO7zMmcMHMCAYpEH/j2hJApaHXSj0ddgbrmUdJ2z
	vZ5DFDR9syTPHrwtRJLPH7tgdiAtUpyXLozL321JIR7sExzONl7IKdpH1Qn0y1I/
	h6mV0Dm+AAJXWtbn08rDW2WWuW4+EBEy12Cfk2r1rF8KT+g3gcc2wLejSACkf7v+
	jKo5SnvIwIMze+Msqjcz/+hbKRdEEoD2zihe6ilMfbR1tCt8GALQVa8YEoHpgkcL
	MWbXSCgM7Q0gf00kHWa3A8rClW0dzW5kJG+InbymtenaDNwoNlFb6DHUdyF//REx
	YjJ6qHf7qFwtXPBiwrZf+VYt5OnjeWW6ybYasfrJiXi1qnd6IM40QCGlR0UXhII=
	=oUn0
	-----END PGP SIGNATURE-----
	"""
	kbase = Keybase('irc')
	verified = kbase.verify(message_good)
	assert verified
	verified = kbase.verify(message_bad)
	assert not verified
	kbase.verify(message_bad, throw_error=True)
	Traceback (most recent call last):
	...
	KeybasePublicKeyVerifyError: signature bad

In the ``message_bad`` case you can see that either the message was tampered with or the signature was faked. In either case you shouldn't trust it because it couldn't be verified correctly.

Verifying an Embedded Signature on a File
-----------------------------------------

Where the file was signed with a ``gpg`` command like so::

    gpg -u keybase.io/irc --sign helloworld.txt

So there is one, binary, file ``helloworld.txt.gpg`` that contains both the data and the signature on the data to verify::

    kbase = Keybase('irc')
    verified = kbase.verify_file('helloworld.txt.gpg')
    assert verified

Verify an Detached Signature on a File
--------------------------------------

Where the file was signed with a ``gpg`` command like so::

	gpg -u keybase.io/irc --detach-sign helloworld.txt

So there are two files:

#. The original data file; and
#. The detached ``.sig`` file that contains the signature for the data.

In this case::

    kbase = Keybase('irc')
    fname = 'helloworld.txt'
    signame = 'helloworld.txt.sig'
    verified = kbase.verify_file(fname, signame)
    assert verified

Encrypting a Message for a Keybase User
---------------------------------------

Given some ``str`` formatted data, you can create an ASCII armored, encrypted ``str`` representation of that data suitable for sending to the user. Only someone with the private key, presumably this Keybase user, will be able to decrypt this data::

    kbase = Keybase('irc')
    instring = 'Hello, world!'
    encrypted = kbase.encrypt(instring)
    assert encrypted
    assert not encrypted.isspace()
    assert encrypted != instring

This ASCII armored approach to encrypting is useful for embedding secret messages in to standard, plaintext communications like emails, tweets or text messages.

Encrypting a File for a Keybase User
------------------------------------

You can create a binary, encrypted file for a user using their Keybase key. Only the user, with their private key, will be able to decrypt the data. The input file contents does not have to be ASCII in this case::

	kbase = Keybase('irc')
	with open('inputfile.bin', 'rb') as infile:
		with open('inputfile.bin.gpg', 'wb') as outfile:
			data = infile.read()
			encrypted_data = kbase.encrypt(data, armor=False)
			outfile.write(encrypted_data.data)
	assert os.path.isfile('inputfile.bin.gpg')

The user can now decrypt ``inputfile.bin.gpg`` with::

	gpg --decrypt inputfile.bin.gpg

They will be prompted for the private key's password.
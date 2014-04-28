'''
.. module:: keybase
   :platform: Unix, Windows
   :synopsis: Python class interface to the keybase.io API.

.. moduleauthor:: Ian Chesal <ian.chesal@gmail.com>

'''

#pylint: disable=R0902
#pylint: disable=R0913
#pylint: disable=C0301
#pylint: disable=W0142

import datetime
import gnupg
import os
import requests
import shutil
import subprocess
import tempfile

def gpg(binary=None):
    '''
    Returns the full path to the gpg instance on this machine. It prefers
    ``gpg2`` but will search for ``gpg`` if it cannot find ``gpg2``.

    I implemented this because the :mod:`gnupg.GPG` class was having a
    hard time dealing with the fact that my Homebrew-installed GPG instance
    was a symlink in the ``/usr/local/bin`` directory instead of a real
    path to a real file.

    If you want to use a binary with a specific name, supply the
    ``binary=bName`` option when you call ``gpg()`` and it will use your
    custom binary name instead.

    On windows you shouldn't need to supply an extension to the command
    like ``.exe`` or ``.cmd`` -- it will figure it out for you.

    Returns ``None`` if it cannot find a gpg2 or gpg instance in your PATH.
    '''
    if binary:
        search_list = list(binary)
    else:
        search_list = ('gpg2', 'gpg')
    for _gpg in search_list:
        mygpg = _which(_gpg)
        if len(mygpg) > 0:
            return os.path.realpath(mygpg[0])
    return None

def _which(executable, flags=os.X_OK):
    '''
    Borrowed from Twisted's :mod:twisted.python.proutils .

    Search PATH for executable files with the given name.

    On newer versions of MS-Windows, the PATHEXT environment variable will be
    set to the list of file extensions for files considered executable. This
    will normally include things like ".EXE". This fuction will also find files
    with the given name ending with any of these extensions.

    On MS-Windows the only flag that has any meaning is os.F_OK. Any other
    flags will be ignored.

    Returns a list of the full paths to files found, in the order in which
    they were found.
    '''
    result = []
    exts = [item for item in os.environ.get('PATHEXT', '').split(os.pathsep) if item]
    path = os.environ.get('PATH', None)
    if path is None:
        return []
    for tpath in os.environ.get('PATH', '').split(os.pathsep):
        tpath = os.path.join(tpath, executable)
        if os.access(tpath, flags):
            result.append(tpath)
        for ext in exts:
            pext = tpath + ext
            if os.access(pext, flags):
                result.append(tpath)
    return result

class Keybase(object):
    '''
    A read-only view of a keybase.io user and their publically available
    keys. This class allows you to do interesting things with someone's
    public key data like encrypt a message for them or verify that a message
    they signed to you was actually signed by them.

    If you supply a username the user's public information will be
    automatically retrieved. If the username doesn't exist a
    :mod:`keybase.KeybaseUserNotFound` exception will be raised.

    If you don't supply a username you can initiate a user lookup by
    using the :func:`keybase.Keybase.lookup` method on the object after
    you create
    it.

    .. note::

        It does not allow you to manipulate the key data in the keybase.io data
        store in any way. If you want to administer a user's keys please see
        :mod:`keybase.KeybaseAdmin`.

    '''

    KEYBASE_BASE_URL = 'https://keybase.io/_/api/'
    KEYBASE_API_VERSION = '1.0'

    def __init__(self, username=None):
        self._username = None
        self._user_object = None
        self.__lookup_performed = False
        if username:
            self.lookup(username)

    @property
    def name(self):
        '''
        The full name of the person associated with this Keybase data.
        '''
        return self._section_getter('profile', 'full_name')

    @property
    def location(self):
        '''
        The geographical location of the person associated with this
        Keybase data.
        '''
        return self._section_getter('profile', 'location')

    @property
    def username(self):
        '''
        The username of the person associated with this Keybase data.
        '''
        return self._username

    @property
    def api_version(self):
        '''
        The Keybase API version in use for this instance.
        '''
        return self.KEYBASE_API_VERSION

    @property
    def is_bound(self):
        '''
        Returns True if this Keybase object instance is bound to a user or
        False if it has yet to be associated with a specific username.
        '''
        if self._username and self._user_object and self.__lookup_performed:
            return True
        return False

    @property
    def public_keys(self):
        '''
        A tuple of all the public keys available for this account. An empty
        tuple is returned if the instance isn't bound to a user or the user
        has no keys.

        >>> kbase = Keybase('irc')
        >>> kbase.public_keys
        (u'primary',)
        '''
        pkeys = list()
        if self._user_object:
            if 'public_keys' in self._user_object:
                pkeys = self._user_object['public_keys'].keys()
        return tuple(pkeys)

    def _section_getter(self, section, key):
        '''
        Gets a value from a specific section of the user data object.

        Returns the value if the user data object has been loaded, the
        section exists in the user data object and the key exists in
        that section in the user data object:

        >>> kbase = Keybase('irc')
        >>> kbase._section_getter('profile', 'full_name')
        u'Ian Chesal'

        Otherwise it returns None if the section doesn't exist:

        >>> if not kbase._section_getter('invalidsectionname', 'full_name'):
        ...    print 'Section not found!'
        Section not found!

        Or the key doesn't exist in the section:

        >>> if not kbase._section_getter('profile', 'invalidkeyname'):
        ...    print 'Key not found!'
        Key not found!

        '''
        if self._user_object:
            if section in self._user_object:
                if key in self._user_object[section]:
                    return self._user_object[section][key]
        return None

    def _raise_unbound_error(self, message):
        '''
        Raises a :mod:`keybase.`KeybaseUnboundInstanceError` if the instance
        isn't currently bound to a real user in the keybase.io data store.
        Appends message to the error when it's raised.
        '''
        if not self.is_bound:
            raise KeybaseUnboundInstanceError(message)

    def get_public_key(self, keyname='primary'):
        '''
        Returns a key named keyname as a :mod:`keybase.KeybasePublicKey` object
        if it exists in the current Keybase instance. Defaults to a key named
        ``primary`` if you opt not to supply a keyname when you call the
        method.

        >>> kbase = Keybase('irc')
        >>> primary_key = kbase.get_public_key()
        >>> primary_key.kid
        u'0101f56ecf27564e5bec1c50250d09efe963cad3138d4dc7f4646c77f6008c1e23cf0a'

        Otherwise it returns None if a key by the name of keyname doesn't
        exist for this user.

        >>> kbase.get_public_key('thiskeydoesnotexist')

        If the instance hasn't been bound to a username yet it throws a
        :mod:`keybase.KeybaseUnboundInstanceError`.

        >>> kbase = Keybase()
        >>> kbase.get_public_key()
        Traceback (most recent call last):
        ...
        KeybaseUnboundInstanceError: Unable to fetch public key
        '''
        self._raise_unbound_error('Unable to fetch public key')
        key = None
        if keyname in self.public_keys:
            key_data = self._user_object['public_keys'][keyname]
            key = KeybasePublicKey(**key_data)
        return key

    def lookup(self, username):
        '''
        Looks up a user in the keybase.io public directory and initializes
        this Keybase class instance with the user's public keybase.io
        details.

        >>> kbase = Keybase()
        >>> kbase.username
        >>> kbase.lookup('irc')
        >>> kbase.username
        'irc'

        The lookup() method can be called until the first successful user
        is found in keybase.io. After that, subsequent lookup calls will
        raise a :mod:`keybase.KeybaseLookupInvalidError` exception:

        >>> kbase.lookup('ab')
        Traceback (most recent call last):
        ...
        KeybaseLookupInvalidError: Keybase object already bound to username 'irc'

        To get the private view of the user you need to authenticate as
        the user using the login() method after successfully looking the
        user up in keybase.io.

        If the user cannot be found a :mod:`keybase.KeybaseUserNotFound`
        exception is raised:

        >>> kbase2 = Keybase()
        >>> kbase2.lookup('abcdefghijklmno123')
        Traceback (most recent call last):
        ...
        KeybaseUserNotFound: ('User abcdefghijklmno123 not found', {'url': u'https://keybase.io/_/api/1.0/user/lookup.json?username=abcdefghijklmno123'})
        '''
        # If this object is already initialized then the user shouldn't
        # be calling this method a second time.
        if self.__lookup_performed:
            raise KeybaseLookupInvalidError(
                'Keybase object already bound to username \'{}\''.format(self._username))
        url = self._build_url('user/lookup.json')
        payload = {'username': username}
        resp = requests.get(url, params=payload, timeout=10)
        resp.raise_for_status()
        jresponse = resp.json()
        # Pendantic searching of the status section of the API's JSON
        # response. We could just leave it up to the 'them' section
        # existing or not but future API changes may require that we
        # handle the response differently based on the statue section
        # in the response and the response codes therein so lets prepare
        # for that now.
        if not 'status' in jresponse or not 'name' in jresponse['status']:
            raise KeybaseError('Malformed API response to user/lookup.json request', {
                'url': resp.url,
                'response': resp.text
                })
        if jresponse['status']['name'] == 'NOT_FOUND':
            raise KeybaseUserNotFound('User {} not found'.format(username), {
                'url': resp.url,
                })
        if jresponse['status']['name'] == 'INPUT_ERROR':
            raise KeybaseUserNotFound('User {} not found'.format(username), {
                'url': resp.url,
                })
        if not 'them' in jresponse:
            raise KeybaseError('Malformed API response to user/lookup.json request', {
                'url': resp.url,
                'response': resp.text
                })
        # Initialize this user from the 'them' part of the reponse.
        self._user_object = jresponse['them']
        self._username = username
        self.__lookup_performed = True

    def verify(self, data, throw_error=False):
        '''
        Equivalent to::

            kbase = Keybase('irc')
            pkey = kbase.get_public_key()
            verified = pkey.verify(some_message)
            assert verified

        It's a convenience method on the Keybase object to do data
        verification with the primary key.

        For more information see :mod:`keybase.KeybasePublicKey.verify`.

        If the instance hasn't been bound to a username yet it throws a
        :mod:`keybase.KeybaseUnboundInstanceError`.
        '''
        self._raise_unbound_error('Unable to fetch public key')
        pkey = self.get_public_key()
        return pkey.verify(
            data,
            throw_error=throw_error)

    def verify_file(self, fname, sigfname=None, throw_error=False):
        '''
        Equivalent to::

            kbase = Keybase('irc')
            pkey = kbase.get_public_key()
            verified = pkey.verify_file(fname, signame)
            assert verified

        It's a convenience method on the Keybase object to do data
        verification with the primary key.

        For more information see :mod:`keybase.KeybasePublicKey.verify_file`.

        If the instance hasn't been bound to a username yet it throws a
        :mod:`keybase.KeybaseUnboundInstanceError`.
        '''
        self._raise_unbound_error('Unable to fetch public key')
        pkey = self.get_public_key()
        return pkey.verify_file(
            fname=fname,
            sigfname=sigfname,
            throw_error=throw_error)

    def encrypt(self, data, **kwargs):
        '''
        Equivalent to::

            kbase = Keybase('irc')
            pkey = kbase.get_public_key()
            verified = pkey.encrypt(data, **kwargs)
            assert verified

        It's a convenience method on the Keybase object to do data
        verification with the primary key.

        For more information see :mod:`keybase.KeybasePublicKey.encrypt`.

        If the instance hasn't been bound to a username yet it throws a
        :mod:`keybase.KeybaseUnboundInstanceError`.
        '''
        self._raise_unbound_error('Unable to fetch public key')
        pkey = self.get_public_key()
        return pkey.encrypt(
            data=data,
            **kwargs)

    @staticmethod
    def _build_url(endpoint):
        '''
        Builds a Keybase API URL for endpoint. Returns the URL as
        a simple string.

        >>> Keybase._build_url('foo')
        'https://keybase.io/_/api/1.0/foo.json'
        >>> Keybase._build_url('/foo/bar.json')
        'https://keybase.io/_/api/1.0/foo/bar.json'
        '''
        if len(endpoint) < 1:
            raise KeybaseError('Missing URL endpoint for API call')
        if endpoint[0] != '/':
            endpoint = '/' + endpoint
        if not endpoint.endswith('.json'):
            # All API calls end with .json (at least for our purposes)
            endpoint = endpoint + '.json'
        url = Keybase.KEYBASE_BASE_URL + Keybase.KEYBASE_API_VERSION + endpoint
        return url

class KeybaseAdmin(Keybase):
    '''
    Extends the :mod:`keybase.Keybase` class to add adminstrative functions
    to what the Keybase class can already do. Allowing you to add keys,
    revoke keys, sign keys and kill all active login sessions for a user.

    In order to use this class you need to be in possession of the login
    password for the keybase.io account.

    .. note::

        This class is still not implemented. The documentation you see here
        is for future reference only.
    '''

    def __init__(self, username):
        Keybase.__init__(self, username)
        self.__salt = None
        self.__session_cookie = None

    @property
    def salt(self):
        '''
        The salt for this login session.
        '''
        return self.__salt

    @property
    def session(self):
        '''
        The session cookie that's tracking this login session.
        '''
        return self.__session_cookie

    def _get_salt(self):
        '''
        The first round of the two round Keybase login procedure. This
        function gets the salt stored for the user as well as a short-lived
        random challenge string in the form of a login session ID.

        The salt is stored in the object instance's _salt property while
        the login session ID is returned by the function.

        If the object has no username property an KeybaseError is thrown.

        >>> kbase = KeybaseAdmin(username='irc')
        >>> print kbase.salt
        None
        >>> login_session = kbase._get_salt()
        >>> print kbase.salt
        5838c199c1b825a069185d5707302693
        '''
        self._raise_unbound_error('Unable to retrieve salt from keybase.io')
        url = self._build_url('getsalt.json')
        payload = {'email_or_username': self._username}
        resp = requests.get(url, params=payload, timeout=10)
        resp.raise_for_status()
        jresponse = resp.json()
        if not 'salt' in jresponse:
            raise KeybaseError('_get_salt(): No salt value returned for login {0}'.format(self._username))
        if not 'login_session' in jresponse:
            raise KeybaseError('_get_salt(): No login_session value returned for login {0}'.format(self._username))
        self.__salt = jresponse['salt']
        return jresponse['login_session']

    def login(self, password):
        '''
        Executes a two-round login procedure for a user using the supplied
        password to authenticate. The first round involves looking up the
        user and getting their salt and a challenge in the form of a login
        session ID. The second round involves computing the password hash
        and using it to answer the password challenge.

        If the login succeeds the method returns True and a session ID is
        stored in the instance along with all the user object details returned
        by the API when a login is successful.

        If login fails the method throws a :mod:`keybase.KeybaseError` with all
        the details for why login failed in the message.
        '''
        self._raise_unbound_error('Unable to log in to keybase.io')
        login_session = self._get_salt()

class KeybasePublicKey(object):
    '''
    A class that represents the public key side of a public/private key pair.

    It is tied very closely to the keybase.io data that's stored for public
    keys in user profiles in the data store. As such, it's meant to be
    initialized with a hash that contains the fields seen in a keybase.io
    public key record.

    Under the hood it uses GnupGP's :py:class:`gnupg.GPG` class to do the
    heavy lifting. It creates a keystore that is unique to this instance of
    the class and loads the public key in to this keystore.

    You won't be able to decrypt with this class because it only contains a public
    key, not a private key. But you can encrypt and and sign:

    >>> kbase = Keybase('irc')
    >>> pkey = kbase.get_public_key()
    >>> pkey.key_fingerprint
    u'7cc0ce678c37fc27da3ce494f56b7a6f0a32a0b9'

    If a valid GPG instance cannot be created when you initialize a KeybasePublicKey
    a KeybasePublicKeyError will be raised.
    '''
    def __init__(self, **kwargs):
        self.__data = dict()
        for key, value in kwargs.iteritems():
            if key == 'mtime' or key == 'ctime':
                self.__data[key] = datetime.datetime.fromtimestamp(int(value))
            else:
                self.__data[key] = value
        self.__cipher_algos = KeybasePublicKey.__get_gpg_config('ciphername')
        self.__digest_algos = KeybasePublicKey.__get_gpg_config('digestname')
        self.__compress_algos = ['ZLIB', 'BZIP2', 'ZIP', 'Uncompressed']
        self.__gpg = None
        self.__tempdir = tempfile.mkdtemp(suffix='.keybase')
        if self.bundle:
            self.__gpg = gnupg.GPG(
                binary=gpg(),
                homedir=self.__tempdir,
                verbose=False,
                use_agent=False)
            import_result = self.__gpg.import_keys(self.bundle)
            # TODO: For some reason importing a single key results in two result
            # entries in the ImportResult.result and ImportResult.fingerprints
            # arrays. I've asked the gnupg devs why this is and I'm waiting to
            # hear back. For now we expect one and only one key to exist in our
            # keyring after import so we'll check all of them an assert they're
            # all carrying the same fingerprint as the key that was loaded in to
            # this instance.
            for fprint in import_result.fingerprints:
                if fprint.lower() != self.key_fingerprint:
                    raise KeybasePublicKeyError('A serious security error has occured: fingerprint mismatch on key import')
        else:
            raise KeybasePublicKeyError('Missing PGP key bundle in init data')
        if not self.__gpg:
            raise KeybasePublicKeyError('Unable to create Keybase public key instance')

    def __del__(self):
        # This makes sure the keyring we created is destroyed when the object
        # gets garbage collected.
        shutil.rmtree(self.__tempdir, ignore_errors=True)

    @property
    def kid(self):
        '''
        The Keybase key ID for this key.
        '''
        return self.__property_getter('kid')

    @property
    def key_type(self):
        '''
        The Keybase key type for this key (integer).
        '''
        return self.__property_getter('key_type')

    @property
    def bundle(self):
        '''
        The GPG key bundle. This is the ASCII representation of the public
        key data associated with the Keybase key.
        '''
        return self.__property_getter('bundle')

    @property
    def ascii(self):
        '''
        Synonym for bundle property.
        '''
        return self.__property_getter('bundle')

    @property
    def mtime(self):
        '''
        The datetime this key was last modified in the Keybase database.
        '''
        return self.__property_getter('mtime')

    @property
    def ctime(self):
        '''
        The datetime this key was created in the keybase database.
        '''
        return self.__property_getter('ctime')

    @property
    def ukbid(self):
        '''
        The UKB ID for the key.
        '''
        return self.__property_getter('ukbid')

    @property
    def key_fingerprint(self):
        '''
        The GPG fingerprint for the key.
        '''
        return self.__property_getter('key_fingerprint').lower()

    @property
    def cipher_algos(self):
        '''
        Returns a tuple of available cypher algorithms that you can use with
        this key to encrypt data. The available algorithms depend entirely
        on the GPG version installed on the machine though most, if not
        all GPG versions, support ``AES256``.

        >>> kbase = Keybase('irc')
        >>> pkey = kbase.get_public_key()
        >>> 'AES256' in pkey.cipher_algos
        True
        '''
        return tuple(self.__cipher_algos)

    @property
    def digest_algos(self):
        '''
        Returns a tuple of available digest algorithms that you can use with
        this key to hash data. The available algorithms depend entirely
        on the GPG version installed on the machine though most, if not
        all GPG versions, support ``SHA512``.

        >>> kbase = Keybase('irc')
        >>> pkey = kbase.get_public_key()
        >>> 'SHA512' in pkey.digest_algos
        True
        '''
        return tuple(self.__digest_algos)

    @property
    def compress_algos(self):
        '''
        Returns a tuple of available compression algorithms that you can use
        with this key to compress encrypted data. The available algorithms
        depend entirely on the GPG version installed on the machine though
        most, if not all GPG versions, support ``ZIP``.

        >>> kbase = Keybase('irc')
        >>> pkey = kbase.get_public_key()
        >>> 'ZIP' in pkey.compress_algos
        True
        '''
        return tuple(self.__compress_algos)

    @staticmethod
    def __get_gpg_config(config):
        '''
        Returns, as a list, the value of the ``config`` property from the
        installed GPG version. If the ``config`` property is a string it
        will be the only element in the list, otherwise it will be a list
        of values the property can support.
        '''
        values = list()
        command = [gpg(), '--with-colons', '--list-config', config]
        output = subprocess.check_output(command)
        output = output.strip()
        (cfg, configname, clist) = output.strip().split(':', 2)
        if cfg == 'cfg' and configname == config and clist:
            values = clist.split(';')
        return values

    def __property_getter(self, prop):
        '''
        Get a random property value from the __data dictionary in the
        object. Returns the value or None if the property isn't in the
        dictionary.
        '''
        value = None
        if prop in self.__data:
            value = self.__data[prop]
        return value

    def verify(self, data, throw_error=False):
        '''
        Verify the signature on the contents of the string ``data``.
        Returns True if the signature was verified with the key, False
        if it was not. If you supply ``throw_error=True`` to the call then
        it will throw a KeybasePublicKeyVerifyError on verification failure
        with a status message that tells you more about why verification
        failed.

        Failure status messages are:

        * invalid gpg key
        * signature bad
        * signature error
        * decryption failed
        * no public key
        * key exp
        * key rev

        For more information what these messages mean please see the
        :py:class:`gnupg._parsers.Verify` manual page.

        >>> message_good = """
        ... -----BEGIN PGP SIGNED MESSAGE-----
        ... Hash: SHA1
        ...
        ... Hello, world!
        ... -----BEGIN PGP SIGNATURE-----
        ... Version: GnuPG v1
        ...
        ... iQEcBAEBAgAGBQJTWHSVAAoJEO7zMmcMHMCAYpEH/j2hJApaHXSj0ddgbrmUdJ2z
        ... vZ5DFDR9syTPHrwtRJLPH7tgdiAtUpyXLozL321JIR7sExzONl7IKdpH1Qn0y1I/
        ... h6mV0Dm+AAJXWtbn08rDW2WWuW4+EBEy12Cfk2r1rF8KT+g3gcc2wLejSACkf7v+
        ... jKo5SnvIwIMze+Msqjcz/+hbKRdEEoD2zihe6ilMfbR1tCt8GALQVa8YEoHpgkcL
        ... MWbXSCgM7Q0gf00kHWa3A8rClW0dzW5kJG+InbymtenaDNwoNlFb6DHUdyF//REx
        ... YjJ6qHf7qFwtXPBiwrZf+VYt5OnjeWW6ybYasfrJiXi1qnd6IM40QCGlR0UXhII=
        ... =oUn0
        ... -----END PGP SIGNATURE-----
        ... """
        >>> message_bad = """
        ... -----BEGIN PGP SIGNED MESSAGE-----
        ... Hash: SHA1
        ...
        ... Hello, another world!
        ... -----BEGIN PGP SIGNATURE-----
        ... Version: GnuPG v1
        ...
        ... iQEcBAEBAgAGBQJTWHSVAAoJEO7zMmcMHMCAYpEH/j2hJApaHXSj0ddgbrmUdJ2z
        ... vZ5DFDR9syTPHrwtRJLPH7tgdiAtUpyXLozL321JIR7sExzONl7IKdpH1Qn0y1I/
        ... h6mV0Dm+AAJXWtbn08rDW2WWuW4+EBEy12Cfk2r1rF8KT+g3gcc2wLejSACkf7v+
        ... jKo5SnvIwIMze+Msqjcz/+hbKRdEEoD2zihe6ilMfbR1tCt8GALQVa8YEoHpgkcL
        ... MWbXSCgM7Q0gf00kHWa3A8rClW0dzW5kJG+InbymtenaDNwoNlFb6DHUdyF//REx
        ... YjJ6qHf7qFwtXPBiwrZf+VYt5OnjeWW6ybYasfrJiXi1qnd6IM40QCGlR0UXhII=
        ... =oUn0
        ... -----END PGP SIGNATURE-----
        ... """
        >>> kbase = Keybase('irc')
        >>> pkey = kbase.get_public_key()
        >>> verified = pkey.verify(message_good)
        >>> assert verified
        >>> verified = pkey.verify(message_bad)
        >>> assert not verified
        >>> pkey.verify(message_bad, throw_error=True)
        Traceback (most recent call last):
        ...
        KeybasePublicKeyVerifyError: signature bad

        If you want to verify the signature on a file (either embedded
        or detached) please see :func:`keybase.KeybasePublicKey.verify_file`
        method.
        '''
        vobj = self.__gpg.verify(data)
        if vobj.valid:
            return True
        if throw_error:
            raise KeybasePublicKeyVerifyError('{}'.format(vobj.status))
        return False

    def verify_file(self, fname, sigfname=None, throw_error=False):
        '''
        Verify the signature on a file named ``fname``. This is a string file
        name, not a file object. If only a ``fname`` is provided the method
        assumes the signature is embedded in the file itself. An embedded
        signature is usually produced like so::

            gpg -u keybase.io/irc --sign helloworld.txt

        If a ``sigfname`` argument is prodived it's assumed to be a path to
        signature file for a detached signature. A detached signature is
        usually produced like so::

            gpg -u keybase.io/irc --detach-sign helloworld.txt

        Returns True if the signature is verifiable with the key, False if it
        is not verifiable.

        If you supply the ``throw_error=True`` option to the call then it will
        throw a KeybasePublicKeyVerifyError on verification failure with a
        status message that tells you more about why the verification failed.

        Failure status messages are:

        * invalid gpg key
        * signature bad
        * signature error
        * decryption failed
        * no public key
        * key exp
        * key rev

        For more information what these messages mean please see the
        :py:class:`gnupg._parsers.Verify` manual page.

        An embedded signature example::

            kbase = Keybase('irc')
            pkey = kbase.get_public_key()
            verified = pkey.verify_file('helloworld.txt.gpg')
            assert verified

        A detached signature example::

            kbase = Keybase('irc')
            pkey = kbase.get_public_key()
            fname = 'helloworld.txt'
            signame = 'helloworld.txt.sig'
            verified = pkey.verify_file(fname, signame)
            assert verified
        '''
        vobj = None
        if not sigfname:
            # The embedded signature version of the GPG call expects
            # a file object, not a file name, for some reason so...
            with open(fname, 'rb') as fobj:
                vobj = self.__gpg.verify_file(fobj)
        else:
            # The detached signature version of the GPG call expects
            # file names so...
            vobj = self.__gpg.verify_file(fname, sigfname)
        if vobj.valid:
            return True
        if throw_error:
            raise KeybasePublicKeyVerifyError('{}'.format(vobj.status))
        return False

    def encrypt(
        self,
        data,
        armor=True,
        cipher_algo=None,
        digest_algo=None,
        compress_algo=None):
        '''
        Encrypt the message contained in the string ``data`` for the owner
        of this KeybasePublicKey instance.

        If ``armor=True`` the output is ASCII armored; otherwise the output
        will be a
        `gnupg._parsers.Crypt object <https://python-gnupg.readthedocs.org/en/latest/gnupg.html#gnupg._parsers.Crypt>`_.

        If encryption fails a KeybasePublicKeyEncryptError is raised.

        If it succeeds data object is returned. Assuming ``armor=True`` the
        returned data is just plain old ASCII text as a ``str()``.

        .. note::

            The remaining options are supplied for maximum flexibility with GPG
            but you can, for the most part, just ignore them and go with the
            defaults if you want the simpilest (but still secure) path to
            encrypting data with this API.

        If ``cipher_algo`` is supplied it should be the name of a cipher
        algorithm to use. The default algorithm is ``AES256`` and you can
        get a list of available algorithms from the
        :func:`keybase.KeybasePublicKey.crypto_algos` parameter.

        If ``digest_algo`` is supplied it should be the name of a digest
        algorithm to use. The default is ``SHA512`` and you can get a list of
        available algorithms from the
        :func:`keybase.KeybasePublicKey.digest_algos` parameter.

        If ``compress_algo`` is supplied it should be the name of a compression
        algorithm to use. The default is ``ZIP`` and you can get a list of
        available algorithms from the
        :func:`keybase.KeybasePublicKey.compress_algos` parameter.

        For more information on how encryption works please see the
        :py:class:`gnupg.encrypt` manual page.

        A simple example::

            kbase = Keybase('irc')
            pkey = kbase.get_public_key()
            instring = 'Hello, world!'
            encrypted = pkey.encrypt(instring)
            assert encrypted
            assert not encrypted.isspace()
            assert encrypted != instring
        '''
        # For a list of things we can put in kwargs see:
        # https://python-gnupg.readthedocs.org/en/latest/gnupg.html#gnupg.GPG.encrypt
        kwargs = dict()
        if cipher_algo:
            if cipher_algo not in self.__cipher_algos:
                raise KeybasePublicKeyEncryptError(
                    'cipher algorithm {} unrecognized'.format(cipher_algo))
            kwargs['cipher_algo'] = cipher_algo
        if digest_algo:
            if digest_algo not in self.__digest_algos:
                raise KeybasePublicKeyEncryptError(
                    'digest algorithm {} unrecognized'.format(digest_algo))
            kwargs['digest_algo'] = digest_algo
        if compress_algo:
            if compress_algo not in self.__compress_algos:
                raise KeybasePublicKeyEncryptError(
                    'compression algorithm {} unrecognized'.format(compress_algo))
            kwargs['compress_algo'] = compress_algo
        else:
            kwargs['compress_algo'] = 'ZIP'
        kwargs['armor'] = armor
        kwargs['encrypt'] = True
        kwargs['symmetric'] = False
        kwargs['always_trust'] = True
        encrypted = self.__gpg.encrypt(
            data,
            self.__gpg.list_keys()[0]['keyid'],
            **kwargs)
        if not encrypted:
            raise KeybasePublicKeyEncryptError('unable to encrypt data')
        if armor:
            encrypted = str(encrypted)
        return encrypted

class KeybaseError(Exception):
    '''
    General error class for Keybase errors.
    '''
    pass

class KeybaseUnboundInstanceError(Exception):
    '''
    Thrown when calling a Keybase object method that requires the object
    be bound to a real user in the keybase store and the instance hasn't
    had such a binding established yet.
    '''
    pass

class KeybaseUserNotFound(Exception):
    '''
    Thrown when calling Keybase.lookup(username) and the username cannot
    be located in the keybase.io public key repository.
    '''
    pass

class KeybaseLookupInvalidError(Exception):
    '''
    Thrown when calling Keybase.lookup(username) on an instance that has
    already been bound to a valid user via another lookup() call.
    '''
    pass

class KeybasePublicKeyError(Exception):
    '''
    Thrown when a KeybasePublicKey cannot be created successfully.
    '''
    pass

class KeybasePublicKeyVerifyError(Exception):
    '''
    Thrown when a KeybasePublicKey cannot verify the signature on a
    data object.
    '''
    pass

class KeybasePublicKeyEncryptError(Exception):
    '''
    Thrown when a KeybasePublicKey cannot perform encryption on some
    data object.
    '''
    pass

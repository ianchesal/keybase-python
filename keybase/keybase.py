'''Python class interface to the keybase.io API.'''

#pylint: disable=R0902

import datetime
import requests
import os

KEYBASE_BASE_URL = 'https://keybase.io/_/api/'
KEYBASE_API_VERSION = '1.0'

class Keybase(object):
    '''
    A read-only view of a keybase.io user and their publically available
    keys. This class allows you to do interesting things with someone's
    public key data like encrypt a message for them or verify that a message
    they signed to you was actually signed by them.

    It does not allow you to manipulate the key data in the keybase.io data
    store in any way. If you want to administer a user's keys please see the
    KeybaseAdmin class.
    '''

    def __init__(self, username=None):
        '''
        Create a new, empty instance of a Keybase object.

        If you supply a username the user's public information will be
        automatically retrieve. If the username doesn't exist a
        KeybaseUserNotFound exception will be raised.

        If you don't supply a username you can initiate a user lookup by
        using the lookup(username) method on the object after you create
        it.
        '''
        self._username = None
        self._user_object = None
        self.__lookup_performed = False
        if username:
            self.lookup(username)

    @property
    def name(self):
        return self._section_getter('profile', 'full_name')

    @property
    def location(self):
        return self._section_getter('profile', 'location')

    @property
    def username(self):
        return self._username

    @property
    def api_version(self):
        return KEYBASE_API_VERSION

    @property
    def is_bound(self):
        if self._username and self._user_object and self.__lookup_performed:
            return True
        return False

    @property
    def public_keys(self):
        '''
        A tuple of all the available public keys available for this
        account. An empty tuple is returned if the instance isn't
        bound to a user or the user has no keys.

        >>> k = Keybase('irc')
        >>> k.public_keys
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

        >>> k = Keybase('irc')
        >>> k._section_getter('profile', 'full_name')
        u'Ian Chesal'

        Otherwise it returns None if the section doesn't exist:

        >>> if not k._section_getter('invalidsectionname', 'full_name'):
        ...    print 'Section not found!'
        Section not found!

        Or the key doesn't exist in the section:

        >>> if not k._section_getter('profile', 'invalidkeyname'):
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
        Raises a KeybaseUnboundInstanceError if the instance isn't currently
        bound to a real user in the keybase.io data store. Appends message
        to the error when it's raised.
        '''
        if not self.is_bound:
            raise KeybaseUnboundInstanceError(message)

    def get_public_key(self, keyname='primary'):
        '''
        Returns a key named keyname as a KeybasePublicKey object if it exists
        in the current Keybase instance. Defaults to a key named 'primary' if
        you opt not to supply a keyname when you call the method.

        >>> k = Keybase('irc')
        >>> primary_key = k.get_public_key()
        >>> primary_key.kid
        u'0101f56ecf27564e5bec1c50250d09efe963cad3138d4dc7f4646c77f6008c1e23cf0a'

        Otherwise it returns None if a key by the name of keyname doesn't
        exist for this user.

        >>> k.get_public_key('thiskeydoesnotexist')

        If the instance hasn't been bound to a username yet it throws a
        KeybaseUnboundInstanceError.

        >>> k = Keybase()
        >>> k.get_public_key()
        Traceback (most recent call last):
        ...
        KeybaseUnboundInstanceError: Unable to fetch public key

        >>>
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

        >>> k = Keybase()
        >>> k.username
        >>> k.lookup('irc')
        >>> k.username
        'irc'

        The lookup() method can be called until the first successful user
        is found in keybase.io. After that, subsequent lookup calls will
        raise a KeybaseLookupInvalidError exception:
        
        >>> k.lookup('ab')
        Traceback (most recent call last):
        ...
        KeybaseLookupInvalidError: Keybase object already bound to username 'irc'

        To get the private view of the user you need to authenticate as
        the user using the login() method after successfully looking the
        user up in keybase.io.

        If the user cannot be found a KeybaseUserNotFound exception is
        raised:

        >>> k2 = Keybase()
        >>> k2.lookup('abcdefghijklmno123')
        Traceback (most recent call last):
        ...
        KeybaseUserNotFound: ('User abcdefghijklmno123 not found', {'url': u'https://keybase.io/_/api/1.0/user/lookup.json?username=abcdefghijklmno123', 'desc': u'missing or invalid input'})
        
        '''
        # If this object is already initialized then the user shouldn't
        # be calling this method a second time.
        if self.__lookup_performed:
            raise KeybaseLookupInvalidError(
                'Keybase object already bound to username \'{}\''.format(self._username))
        url = KEYBASE_BASE_URL + KEYBASE_API_VERSION + '/user/lookup.json'
        payload = { 'username': username }
        r = requests.get(url, params=payload, timeout=10)
        r.raise_for_status()    
        jresponse = r.json()
        # Pendantic searching of the status section of the API's JSON
        # response. We could just leave it up to the 'them' section
        # existing or not but future API changes may require that we
        # handle the response differently based on the statue section
        # in the response and the response codes therein so lets prepare
        # for that now.
        if not 'status' in jresponse or not 'name' in jresponse['status']:
            raise KeybaseError('Malformed API response to user/lookup.json request', {
                'url': r.url,
                'response': r.text
                })
        if jresponse['status']['name'] == 'NOT_FOUND':
            raise KeybaseUserNotFound('User {} not found'.format(username), {
                'url': r.url,
                })
        if jresponse['status']['name'] == 'INPUT_ERROR':
            raise KeybaseUserNotFound('User {} not found'.format(username), {
                'url': r.url,
                'desc': jresponse['status']['desc'],
                })
        if not 'them' in jresponse:
            raise KeybaseError('Malformed API response to user/lookup.json request', {
                'url': r.url,
                'response': r.text
                })
        # Initialize this user from the 'them' part of the reponse.
        self._user_object = jresponse['them']
        self._username = username
        self.__lookup_performed = True

class KeybaseAdmin(Keybase):
    '''
    Extends the Keybase class to add adminstrative functions to what the
    Keybase class can already do. Allowing you to add keys, revoke keys,
    sign keys and kill all active login sessions for a user.

    In order to use this class you need to be in possession of the login
    password for the keybase.io account.

    TODO: Implement this class.
    '''

    def __init__(self, username):
        Keybase.__init__(self, username)
        self.__salt = None
        self.__session_cookie = None

    @property
    def salt(self):
        return self.__salt

    @property
    def session(self):
        return self.__session_cookie

    def _get_salt(self):
        '''
        The first round of the two round Keybase login procedure. This
        function gets the salt stored for the user as well as a short-lived
        random challenge string in the form of a login session ID.

        The salt is stored in the object instance's _salt property while
        the login session ID is returned by the function.

        If the object has no username property an KeybaseError is thrown.

        >>> k = KeybaseAdmin(username='irc')
        >>> print k.salt
        None
        >>> login_session = k._get_salt()
        >>> print k.salt
        5838c199c1b825a069185d5707302693
        '''
        self._raise_unbound_error('Unable to retrieve salt from keybase.io')
        url = KEYBASE_BASE_URL + KEYBASE_API_VERSION + '/getsalt.json'
        payload = { 'email_or_username': self._username }
        r = requests.get(url, params=payload, timeout=10)
        r.raise_for_status()
        jresponse = r.json()
        if not 'salt' in jresponse:
            raise KeybaseError('_get_salt(): No salt value returned for login {0}'.format(login_id))
        if not 'login_session' in jresponse:
            raise KeybaseError('_get_salt(): No login_session value returned for login {0}'.format(login_id))
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

        If login fails the method throws a KeybaseError with all the details
        for why login failed in the message.
        '''
        self._raise_unbound_error('Unable to log in to keybase.io')
        login_session = self._get_salt()
        # TODO: Lots of work here!

class KeybasePublicKey(object):
    '''
    A class that represents the public key side of a public/private key pair.

    It is tied very closely to the keybase.io data that's stored for public
    keys in user profiles in the data store. As such, it's meant to be
    initialized with a hash that contains the fields seen in a keybase.io
    public key record.

    >>> key_data = {
    ... "kid": "0101a55950dc685d1ae098b5e261edc6aa1ac4835e82e5c7eef6aad98c12c4fdaef50a",
    ... "key_type": 1,
    ... "bundle": "-----BEGIN PGP PUBLIC KEY BLOCK----- KJ234990jkdjlasdkfj093lkjdkfjol -----END PGP PUBLIC KEY BLOCK-----",
    ... "mtime": 1396741239,
    ... "ctime": 1396741239,
    ... "ukbid": "c783ab0c262f38837d325d8be4e5ae11",
    ... "key_fingerprint": "ef8febc949b9d15057f6d636102c7b498133f0fd"
    ... }
    >>> kpk = KeybasePublicKey(**key_data)
    >>> kpk.kid == key_data['kid']
    True
    >>> kpk.bundle == key_data['bundle']
    True
    >>> kpk.key_fingerprint == key_data['key_fingerprint']
    True
    >>> print kpk.ctime
    2014-04-05 16:40:39

    '''
    def __init__(self, **kwargs):
        self.__data = dict()
        for key, value in kwargs.iteritems():
            if key == 'mtime' or key == 'ctime':
                self.__data[key] = datetime.datetime.fromtimestamp(int(value))
            else:
                self.__data[key] = value

    @property
    def kid(self):
        return self.__property_getter('kid')

    @property
    def key_type(self):
        return self.__property_getter('key_type')

    @property
    def bundle(self):
        return self.__property_getter('bundle')

    @property
    def mtime(self):
        return self.__property_getter('mtime')

    @property
    def ctime(self):
        return self.__property_getter('ctime')

    @property
    def ukbid(self):
        return self.__property_getter('ukbid')

    @property
    def key_fingerprint(self):
        return self.__property_getter('key_fingerprint')

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
    

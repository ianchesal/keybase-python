'''Python class interface to the keybase.io API.'''

#pylint: disable=R0902

import requests
import os

KEYBASE_BASE_URL = 'https://keybase.io/_/api/'
KEYBASE_API_VERSION = '1.0'

class Keybase(object):

    def __init__(self, username=None):
        '''
        Create a new, empty instance of a Keybase object.

        If you supply a username the user's public information will be
        automatically retrieve. If the username doesn't exist a
        KeybaseUserNotFound exception will be raised.

        If you don't supply a username you can initiate a user look by
        using the lookup(username) method on the object after you create
        it.
        '''
        self.__username=None
        self.__lookup_performed=False
        self.__salt=None
        self.__session_cookie=None
        self.__user_object=None
        if username:
            self.lookup(username)

    @property
    def name(self):
        '''
        >>> k = Keybase('irc')
        >>> k.name
        u'Ian Chesal'
        '''
        if self.__user_object:
            if 'profile' in self.__user_object:
                if 'full_name' in self.__user_object['profile']:
                    return self.__user_object['profile']['full_name']
        return None

    @property
    def username(self):
        return self.__username

    @property
    def api_version(self):
        return KEYBASE_API_VERSION

    @property
    def salt(self):
        return self.__salt

    @property
    def session(self):
        return self.__session_cookie

    def lookup(self, username):
        '''
        Looks up a user in the keybase.io public directory and initializes
        this Keybase class instance with the user's public keybase.io
        details.

        To get the private view of the user you need to authenticate as
        the user using the login() method after successfully looking the
        user up in keybase.io.

        The lookup() method can be called until the first successful user
        is found in keybase.io. After that, subsequent lookup calls will
        raise a KeybaseLookupInvalidError exception.

        If the user cannot be found a KeybaseUserNotFound exception is
        raised.
        '''
        # If this object is already initialized then the user shouldn't
        # be calling this method a second time.
        if self.__lookup_performed:
            raise KeybaseLookupInvalidError(
                'Keybase object already bound to username \'{}\''.format(self.__username))
        url=KEYBASE_BASE_URL + KEYBASE_API_VERSION + '/user/lookup.json'
        payload={ 'username': username }
        r=requests.get(url, params=payload, timeout=10)
        r.raise_for_status()    
        jresponse=r.json()
        if not 'them' in jresponse:
            raise KeybaseUserNotFound('User {} not found'.format(username))
        # Initialize this user from the 'them' part of the reponse.
        self.__user_object = jresponse['them']
        self.__username = username

    def _get_salt(self):
        '''
        The first round of the two round Keybase login procedure. This
        function gets the salt stored for the user as well as a short-lived
        random challenge string in the form of a login session ID.

        The salt is stored in the object instance's _salt property while
        the login session ID is returned by the function.

        If the object has no email and no username property an KeybaseError
        is thrown. Otherwise the object prefers the username over the
        email if both are set.

        >>> keybase=Keybase(username='irc')
        >>> print keybase.salt
        None
        >>> login_session=keybase._get_salt()
        >>> print keybase.salt
        5838c199c1b825a069185d5707302693
        '''
        if not self.__username:
            raise KeybaseError('Unable to retrieve salt: no user bound to this class instance')
        url=KEYBASE_BASE_URL + KEYBASE_API_VERSION + '/getsalt.json'
        payload={ 'email_or_username': self.__username }
        r=requests.get(url, params=payload, timeout=10)
        # Raise a requests.exceptions.HTTPError if the response
        # was not successful.
        r.raise_for_status()
        jresponse=r.json()
        if not 'salt' in jresponse:
            raise KeybaseError('_get_salt(): No salt value returned for login {0}'.format(login_id))
        if not 'login_session' in jresponse:
            raise KeybaseError('_get_salt(): No login_session value returned for login {0}'.format(login_id))
        self.__salt=jresponse['salt']
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
        pass

class KeybaseError(Exception):
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
    

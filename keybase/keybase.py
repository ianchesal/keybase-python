'''Python class interface to the keybase.io API.'''

import json
import os

class Keybase(object):
    '''
    >>> kbase = Keybase()
    '''

    def __init__(self, *args, **kwargs):
        self._email = None
        self._name = None
        self._username = None
        self._salt = None
        self._login_session = None
        self._session_cookie = None
        self._api_version = '1.0'
        self._base_url = 'https://keybase.io/_/api/'
        if 'email' in kwargs:
            self._email = kwargs['email']
        if 'name' in kwargs:
            self._name = kwargs['name']
        if 'username' in kwargs:
            self._username = kwargs['username']
    
    @property
    def api_version(self):
        '''
        Returns the version of the API in use as a string.

        >>> keybase = Keybase()
        >>> keybase.api_version
        '1.0'
        '''
        return self._api_version

    def user(self):
        '''
        Returns a tuple of (email, name, username) details for the user
        associated with this keybase instance.

        >>> keybase = Keybase(
        ... email='example@example.com',
        ... name='Example Example',
        ... username='example'
        ... )
        >>> keybase.user()
        ('example@example.com', 'Example Example', 'example')
        '''
        return (self._email, self._name, self._username)

class KeybaseError(Exception):
    '''
    For now just a virtual class.
    '''
    pass

'''
.. moduleauthor:: Ian Chesal <ian.chesal@gmail.com>
'''

from __future__ import absolute_import

from . import keybase
from .keybase import Keybase, KeybaseAdmin, KeybasePublicKey, gpg

__version__ = '0.1.1'

# do not set __package__ = "keybase", else we will end up with
# keybase.<*allofthethings*>
__all__ = ['Keybase', 'KeybaseAdmin', 'KeybasePublicKey']

# avoid the "from keybase import keybase" idiom
del keybase

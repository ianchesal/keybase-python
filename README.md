# keybase-python

A Python implementation of the keybase.io API

## What is Keybase?

From [their website](https://keybase.io/):

> Keybase is two things.
> 
> 1. a public, publicly-auditable directory of keys and identity proofs
> 1. a protocol (this API) for accessing the directory

Keybase has an existing command line written in Node.js as well as [a well documented HTTP API](https://keybase.io/__/api-docs/1.0). This Python API is mostly an experiment for my own edification and hopefully it becomes something useful for everyone. I was smitten with Keybase's nice HTML API and thought, "Why not?".

## Documentation

The official documentation for the project can be found here: https://readthedocs.org/projects/keybase-python-api/

### Installation

    pip install keybase

## Development

### Continuous Integration

I'm using Travis CI to build and test on every push to the public github repository. You can find the Travis CI page for this project here: https://travis-ci.org/ianchesal/keybase-python/

The project is currently setup in Travis to test Python 2.6, 2.7 and 3.3. But only 2.7 is being targetted at this point and time and 2.6, 3.3 are listed as allowed-to-fail in the .travis.yml file for the project.

### Branching in Git

I'm using [git-flow](http://nvie.com/posts/a-successful-git-branching-model/) for development in git via github. I've loved the branching model git-flow proposed from day one and the addon to git makes it very intuitive and easy to follow. I generally don't push my `feature/*` branches to the public repository; I do keep `development` and `master` up to date here though.

### TODO Work

Please see [TODO.md](TODO.md) for the short list of big things I thought worth writing down.

## Contact Me

Questions or comments about `keybase`? Hit me up at ian.chesal@gmail.com.

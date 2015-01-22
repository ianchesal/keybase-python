# See: https://github.com/jeffknupp/sandman/blob/develop/Makefile
# For the inspiration for this Makefile.

.PHONY: docs release clean

setup: clean
	pip install --upgrade -r requirements.txt

clean:
	rm -rf .tox
	rm -rf test/__pycache__
	rm -rf docs/generated
	rm -rf docs/_build
	rm -rf keybase.egg-info

test: clean
		tox

docs:
	sphinx-build -aE docs docs/generated

release: test docs
	open docs/generated/index.html
	open htmlcov/index.html
	vim keybase/__init__.py

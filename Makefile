# See: https://github.com/jeffknupp/sandman/blob/develop/Makefile
# For the inspiration for this Makefile.

.PHONY: docs release clean

clean:
	rm -rf .tox
	rm -rf test/__pycache__

test: clean
		tox

docs:
	sphinx-build -aE docs docs/generated

release: test docs
	open docs/generated/index.html
	open htmlcov/index.html
	vim keybase/__init__.py
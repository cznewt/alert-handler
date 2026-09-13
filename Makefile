# make is the convention on the machines that have no just; every target maps to a recipe
.PHONY: test test-all venv image demo
test: ; just test
test-all: ; just test-all
venv: ; just venv
image: ; just image
demo: ; just demo

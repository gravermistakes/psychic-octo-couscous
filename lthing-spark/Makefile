SHELL := /bin/bash
export PATH := /root/.alire/bin:$(PATH)

.PHONY: build test prove clean
build:
	gprbuild -P lthing.gpr || true
test:
	./run_tests.sh
prove:
	gnatprove -P lthing.gpr --level=2 --report=all -j0
clean:
	rm -rf obj obj_prove obj_tests

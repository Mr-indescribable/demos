all:
	./setup.py build;
	make pkg;

pkg:
	./mkpkg.py

test:
	./run-test.py;

clean:
	./setup.py clean;
	find nvld -name "*.c" -delete;

clean-all:
	make clean;
	rm build -rf;
	rm atf -rf;

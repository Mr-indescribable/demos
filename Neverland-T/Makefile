all:
	./setup.py build;
	make pkg;

pkg:
	./mkpkg.py

test:
	./run-test.py;

clean:
	find nvld -name "*.c" -delete;
	rm build -rf;
	rm atf -rf;

clean-tmpf:
	./setup.py clean;
	find nvld -name "*.c" -delete;

all:
	rustc -O -C lto=fat --emit=obj --crate-type=lib ./test.rs
	ld.lld-10 -static -o test test.o
	readelf -l ./test
	objcopy -O binary --only-section=.text ./test ./test.bin
	ndisasm -b64 ./test.bin

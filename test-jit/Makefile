all:
	rustc -O -C lto=fat --emit=obj --crate-type=lib -C panic=abort ./test.rs
	ld.lld-10 -static -o test test.o
	readelf -l ./test
#	objcopy -O binary --only-section=.text ./test ./test.bin
	objcopy -O binary ./test ./test.bin
#	ndisasm -b64 ./test.bin

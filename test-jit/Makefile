all:
	# Compile the Rust file to an object
	clang++ -O3 -Wall -Wno-unused-label -Werror -o ./test.o -c ./test.cpp

	# Strip everyting exept for the next sections
	#objcopy --only-section=.text* ./test.o #objdump -h ./test.o

	# Link into a static binary, this will fail if the file refereced
	# any section other than text
	ld.lld-10 --nmagic --entry=entry -static -o test test.o

	readelf -l ./test

	# Convert to a binary file
	objcopy -O binary ./test ./test.bin

	ndisasm -b64 ./test.bin

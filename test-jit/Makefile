all:
	# Compile the Rust file to an object
	clang -o ./test.o -c ./test.c

	# Strip everyting exept for the next sections
	objcopy --only-section=.text* ./test.o #objdump -h ./test.o

	# Link into a static binary, this will fail if the file refereced
	# any section other than text
	ld.lld-10 -static -o test test.o

	# Convert to a binary file
	objcopy -O binary ./test ./test.bin

	ndisasm -b64 ./test.bin

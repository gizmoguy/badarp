badarp.o: badarp.c
	clang -O2 -target bpf \
		-I/usr/include/x86_64-linux-gnu \
		-c $< -o $@

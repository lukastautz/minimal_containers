default:
	diet gcc -static -O3 -Ofast -Wno-deprecated-declarations -Wno-unused-result container.c -o container
	elftrunc container container
install: default
	cp container /bin

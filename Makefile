default:
	diet gcc -static -O3 -Ofast -Wno-deprecated-declarations container.c -o container
	elftrunc container container

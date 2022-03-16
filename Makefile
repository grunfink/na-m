PREFIX=/usr/local

na-m: na.h na.o na-monocypher.o monocypher.o
	$(CC) -g -Wall na.o na-monocypher.o monocypher.o -o $@

monocypher.o: monocypher.c monocypher.h
	$(CC) -g -Wall -Wextra -O3 -march=native -c $<

na-monocypher.o: na-monocypher.c na.h
	$(CC) -g -Wall -c $<

na.o: na.c na.h
	$(CC) -g -Wall -c $<

install:
	install -m 755 na-m $(PREFIX)/bin/na-m

uninstall:
	rm -f $(PREFIX)/bin/na-m

dist: clean
	cd .. && tar czvf na-m/na-m.tar.gz na-m/*

clean:
	rm -f *.o na-m *.tar.gz *.asc

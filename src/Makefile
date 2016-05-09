
CC=cc

# These are here for OS X assuming libarchive is installed via homebrew.
# You may want to remove or tweak them on Linux
CFLAGS=-I/usr/local/opt/libarchive/include
LDFLAGS=-L/usr/local/opt/libarchive/lib

ota2tar: ota2tar.o
	$(CC) $(LDFLAGS) -o $@ $^ -larchive


clean:
	rm ota2tar *.o

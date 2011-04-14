CFLAGS=-I/usr/include/libmemcached
LDFLAGS=-lmemcached
APXS=/usr/sbin/apxs2

.SUFFIXES: .c .o .la

.c.la:
	$(APXS) $(LDFLAGS) $(CFLAGS) -c $< 

all:  mod_auth_memcookie.la

install: mod_auth_memcookie.la
	$(APXS) -i $?

clean:
	-rm -f *.o *.lo *.la *.slo 
	-rm -rf .libs 

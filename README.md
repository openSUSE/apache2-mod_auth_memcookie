apache2-mod_auth_memcookie-1.0.3
================================

This is 1.0.2 mod_auth_memcookie patched to compile on Apache 2.4

The source is from here: http://sourceforge.net/projects/authmemcookie and then
patched. 

Requires
===============================

Libmemcache
A patched version is needed, available here: 
https://github.com/richp10/libmemcache-1.4.0.rc2-patched

Memcache
To Compile mod_auth_memecahce I needed a minor hack to memcache source code
nano /memcached/memcached-1.4.15/memcached.h
(after the other defines add the following lines)
    #ifdef OK
    #undef OK
    #endif

UPDATED VERSION
================
There is a more recent version of mod_auth_memcookie from the original author
This has added several features and also ported to use libmemcached rather
than libmemcache. 

Unfortunately, this version does not compile for Apache 2.4. Version numbers 
are now a little confusing as the more up to date version is still shown as 1.0.2

https://github.com/richp10/apache2-mod_auth_memcookie





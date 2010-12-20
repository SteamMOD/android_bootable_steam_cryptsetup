#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "internal.h"

extern struct hash_backend hash_gcrypt_backend;
extern struct hash_backend hash_openssl_backend;
extern struct setup_backend setup_libdevmapper_backend;

#ifdef USE_PLUGINS
static void init_plugins(void)
{
}
#else /* USE_PLUGINS */
#	define init_plugins()	do { } while(0)
#endif /* USE_PLUGINS */

static struct hash_backend *hash_backends[] = {
#ifdef BUILTIN_GCRYPT
	&hash_gcrypt_backend,
#endif
#ifdef BUILTIN_OPENSSL
	&hash_openssl_backend,
#endif
	NULL
};

static struct setup_backend *setup_backends[] = {
#ifdef BUILTIN_LIBDEVMAPPER
	&setup_libdevmapper_backend,
#endif
	NULL
};

struct hash_backend *get_hash_backend(const char *name)
{
	struct hash_backend **backend;

	init_plugins();

	for(backend = hash_backends; *backend; backend++)
		if (!name || strcmp(name, (*backend)->name) == 0)
			break;

	return *backend;
}

void put_hash_backend(struct hash_backend *backend)
{
}

int hash(const char *backend_name, const char *hash_name,
         char *result, size_t size,
         const char *passphrase, size_t sizep)
{
	struct hash_backend *backend;
	struct hash_type *hashes = NULL, *hash;
	char hash_name_buf[256], *s;
	size_t pad = 0;
	int r = -ENOENT;

	if (strlen(hash_name) >= sizeof(hash_name_buf)) {
		set_error("hash name too long: %s", hash_name);
		return -ENAMETOOLONG;
	}

	if ((s = strchr(hash_name, ':'))) {
		size_t hlen;
		strcpy(hash_name_buf, hash_name);
		hash_name_buf[s-hash_name] = '\0';
		hash_name = hash_name_buf;
		hlen = atoi(++s);
		if (hlen > size) {
			set_error("requested hash length (%zd) > key length (%zd)", hlen, size);
			return -EINVAL;
		}
		pad = size-hlen;
		size = hlen;
	}

	backend = get_hash_backend(backend_name);
	if (!backend) {
		set_error("No hash backend found");
		return -ENOSYS;
	}

	hashes = backend->get_hashes();
	if (!hashes) {
		set_error("No hash functions available");
		goto out;
	}

	for(hash = hashes; hash->name; hash++)
		if (strcmp(hash->name, hash_name) == 0)
			break;
	if (!hash->name) {
		set_error("Unknown hash type %s", hash_name);
		goto out;
	}

	r = hash->fn(hash->private, size, result, sizep, passphrase);
	if (r < 0) {
		set_error("Error hashing passphrase");
		goto out;
	}

	if (pad) {
		memset(result+size, 0, pad);
	}

out:
	if (hashes)
		backend->free_hashes(hashes);
	put_hash_backend(backend);

	return r;
}

struct setup_backend *get_setup_backend(const char *name)
{
	struct setup_backend **backend;

	init_plugins();

	for(backend = setup_backends; *backend; backend++)
		if (!name || strcmp(name, (*backend)->name) == 0)
			break;

	return *backend;
}

void put_setup_backend(struct setup_backend *backend)
{
#ifdef USE_PLUGINS
#endif
}

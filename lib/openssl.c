#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include "libcryptsetup.h"
#include "internal.h"

#define NUM_DIGESTS		5

typedef enum _e_digests
{
	DIGEST_MD5 = 0,
	DIGEST_SHA1,
	DIGEST_SHA256,
	DIGEST_SHA512,
	DIGEST_RIPEMD160
} digests_t;

static const char *digest_names[] = {
	"md5",
	"sha1",
	"sha256",
	"sha512",
	"ripemd160"
};


int init_openssl(void)
{
	static int inited = 0;
	if (!inited) {
		inited = 1;
		OpenSSL_add_all_digests();
	} 
	return 0;
}

static int openssl_hash_md5 (void *data, int size, char *key,
                       int sizep, const char *passphrase)
{
	int len = MD5_DIGEST_LENGTH;
	int round, i;
	unsigned char md[MD5_DIGEST_LENGTH];
	MD5_CTX ctx;

	if (!MD5_Init(&ctx))
		return -1;

	for(round = 0; size; round++) {
		/* hack from hashalot to avoid null bytes in key */
		for(i = 0; i < round; i++)
			if (!MD5_Update(&ctx, "A", 1))
				return -1;

		if (!MD5_Update(&ctx, passphrase, sizep))
			return -1;

		if (!MD5_Final(md, &ctx))
			return -1;
		if (len > size)
			len = size;
		memcpy(key, md, len);

		key += len;
		size -= len;
		/* not needed, *_Final() resets the hash */
		/*if (size)
			if (!MD5_Init(&ctx))
				return -1;*/
	}
	memset(md, 0x00, MD5_DIGEST_LENGTH);

	return 0;
}

static int openssl_hash_sha1 (void *data, int size, char *key,
                       int sizep, const char *passphrase)
{
	int len = SHA_DIGEST_LENGTH;
	int round, i;
	unsigned char md[SHA_DIGEST_LENGTH];
	SHA_CTX ctx;

	if (!SHA_Init(&ctx))
		return -1;

	for(round = 0; size; round++) {
		/* hack from hashalot to avoid null bytes in key */
		for(i = 0; i < round; i++)
			if (!SHA_Update(&ctx, "A", 1))
				return -1;

		if (!SHA_Update(&ctx, passphrase, sizep))
			return -1;

		if (!SHA_Final(md, &ctx))
			return -1;
		if (len > size)
			len = size;
		memcpy(key, md, len);

		key += len;
		size -= len;
		/* not needed, *_Final() resets the hash */
		/*if (size)
			if (!SHA_Init(&ctx))
				return -1;*/
	}
	memset(md, 0x00, SHA_DIGEST_LENGTH);

	return 0;
}

static int openssl_hash_sha256 (void *data, int size, char *key,
                       int sizep, const char *passphrase)
{
	int len = SHA256_DIGEST_LENGTH;
	int round, i;
	unsigned char md[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	if (!SHA256_Init(&ctx))
		return -1;

	for(round = 0; size; round++) {
		/* hack from hashalot to avoid null bytes in key */
		for(i = 0; i < round; i++)
			if (!SHA256_Update(&ctx, "A", 1))
				return -1;

		if (!SHA256_Update(&ctx, passphrase, sizep))
			return -1;

		if (!SHA256_Final(md, &ctx))
			return -1;
		if (len > size)
			len = size;
		memcpy(key, md, len);

		key += len;
		size -= len;
		/* not needed, *_Final() resets the hash */
		/*if (size)
			if (!SHA256_Init(&ctx))
				return -1;*/
	}
	memset(md, 0x00, SHA256_DIGEST_LENGTH);

	return 0;
}

static int openssl_hash_sha512 (void *data, int size, char *key,
                       int sizep, const char *passphrase)
{
	int len = SHA512_DIGEST_LENGTH;
	int round, i;
	unsigned char md[SHA512_DIGEST_LENGTH];
	SHA512_CTX ctx;

	if (!SHA512_Init(&ctx))
		return -1;

	for(round = 0; size; round++) {
		/* hack from hashalot to avoid null bytes in key */
		for(i = 0; i < round; i++)
			if (!SHA512_Update(&ctx, "A", 1))
				return -1;

		if (!SHA512_Update(&ctx, passphrase, sizep))
			return -1;

		if (!SHA512_Final(md, &ctx))
			return -1;
		if (len > size)
			len = size;
		memcpy(key, md, len);

		key += len;
		size -= len;
		/* not needed, *_Final() resets the hash */
		/*if (size)
			if (!SHA512_Init(&ctx))
				return -1;*/
	}
	memset(md, 0x00, SHA512_DIGEST_LENGTH);

	return 0;
}

static int openssl_hash_ripemd160 (void *data, int size, char *key,
                       int sizep, const char *passphrase)
{
	int len = RIPEMD160_DIGEST_LENGTH;
	int round, i;
	unsigned char md[RIPEMD160_DIGEST_LENGTH];
	RIPEMD160_CTX ctx;

	if (!RIPEMD160_Init(&ctx))
		return -1;

	for(round = 0; size; round++) {
		/* hack from hashalot to avoid null bytes in key */
		for(i = 0; i < round; i++)
			if (!RIPEMD160_Update(&ctx, "A", 1))
				return -1;

		if (!RIPEMD160_Update(&ctx, passphrase, sizep))
			return -1;

		if (!RIPEMD160_Final(md, &ctx))
			return -1;
		if (len > size)
			len = size;
		memcpy(key, md, len);

		key += len;
		size -= len;
		/* not needed, *_Final() resets the hash */
		/*if (size)
			if (!RIPEMD160_Init(&ctx))
				return -1;*/
	}
	memset(md, 0x00, RIPEMD160_DIGEST_LENGTH);

	return 0;
}

static struct hash_type *openssl_get_hashes(void)
{
	struct hash_type *hashes;
	int size = NUM_DIGESTS;
	int i;

	hashes = malloc(sizeof(*hashes) * (size + 1));
	if (!hashes)
		return NULL;

	for(i = 0; i < size; i++) {
		hashes[i].name = NULL;
		hashes[i].private = NULL;
	}

	for(i = 0; i < size; i++) {
		hashes[i].name = strdup(digest_names[i]);
		if(!hashes[i].name)
			goto err;
		/*hashes[i].private = ;
		if(!hashes[i].private)
			goto err;*/
		switch (i)
		{
			case DIGEST_MD5:
				hashes[i].fn = openssl_hash_md5;
				break;
			case DIGEST_SHA1:
				hashes[i].fn = openssl_hash_sha1;
				break;
			case DIGEST_SHA256:
				hashes[i].fn = openssl_hash_sha256;
				break;
			case DIGEST_SHA512:
				hashes[i].fn = openssl_hash_sha512;
				break;
			case DIGEST_RIPEMD160:
				hashes[i].fn = openssl_hash_ripemd160;
				break;
			default:
				goto err;
		}
	}
	hashes[i].name = NULL;
	hashes[i].private = NULL;
	hashes[i].fn = NULL;

	return hashes;

err:
	for(i = 0; i < size; i++) {
		if (hashes[i].name) free(hashes[i].name);
		if (hashes[i].private) free(hashes[i].private);
	}
	free(hashes);

	return NULL;
}

static void openssl_free_hashes(struct hash_type *hashes)
{
	struct hash_type *hash;

	for(hash = hashes; hash->name; hash++) {
		if (hash->name) free(hash->name);
		if (hash->private) free(hash->private);
	}
	free(hashes);
}

struct hash_backend hash_openssl_backend = {
	.name = "openssl",
	.get_hashes = openssl_get_hashes,
	.free_hashes = openssl_free_hashes
};

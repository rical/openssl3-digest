/*
 * OpenSSL 3.0 file digest example.
 *
 * Calculates the md5, sha1, sha256 and sha512 sum of a passed file using
 * "high level EVP_ functions" instead of deprecated "low level functions"
 * such as SHA256_Update.
 */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>
#include <errno.h>

#define BLKSIZE 1024

static int digest_file(FILE *fp, EVP_MD_CTX *ctx)
{
	unsigned char buf[BLKSIZE];
	size_t n;

	rewind(fp);

	while (!feof(fp)) {
		n = fread(buf, 1, BLKSIZE, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Reading file\n");
			return 1;
		} else if (feof(fp) && (n == 0)) {
			break;
		}

		EVP_DigestUpdate(ctx, buf, n);
	}

	return 0;
}

static int calc(FILE *fp, const char *name, const EVP_MD *type, size_t len)
{
	unsigned char *buf;
	EVP_MD_CTX *ctx;
	int err;
	int i;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return 1;

	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, type, NULL);

	err = digest_file(fp, ctx);
	if (err) {
		EVP_MD_CTX_free(ctx);
		return err;
	}

	buf = malloc(len);
	if (!buf) {
		EVP_MD_CTX_free(ctx);
		return 1;
	}

	EVP_DigestFinal_ex(ctx, buf, NULL);
	EVP_MD_CTX_free(ctx);

	printf("%-6s : ", name);
	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");

	free(buf);

	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fp;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s FILENAME\n", argv[0]);
		return EXIT_FAILURE;
	}

	fp = fopen(argv[1], "rb");
	if (!fp) {
		perror("Error, opening file");
		return EXIT_FAILURE;
	}

	if (calc(fp, "md5", EVP_md5(), MD5_DIGEST_LENGTH))
		fprintf(stderr, "Error, calculating MD5\n");
	if (calc(fp, "sha1", EVP_sha1(), SHA_DIGEST_LENGTH))
		fprintf(stderr, "Error, calculating SHA1\n");
	if (calc(fp, "sha256", EVP_sha256(), SHA256_DIGEST_LENGTH))
		fprintf(stderr, "Error, calculating SHA256\n");
	if (calc(fp, "sha512", EVP_sha512(), SHA512_DIGEST_LENGTH))
		fprintf(stderr, "Error, calculating SHA512\n");

	fclose(fp);

	return EXIT_SUCCESS;
}

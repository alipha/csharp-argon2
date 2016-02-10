#include "libargon2.h"

/**
* This file is simply to proxy the argon2 functions so that I export with dllexport
* without modifying the original argon2.h header
*/

int crypto_argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
	const uint32_t parallelism, const void *pwd,
	const size_t pwdlen, const void *salt,
	const size_t saltlen, void *hash,
	const size_t hashlen, char *encoded,
	const size_t encodedlen, argon2_type type) 
{
	return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen, encoded, encodedlen, type);
}

int crypto_argon2_verify(const char *encoded, const void *pwd,
	const size_t pwdlen, argon2_type type)
{
	return argon2_verify(encoded, pwd, pwdlen, type);
}

const char *crypto_argon2_error_message(int error_code)
{
	return argon2_error_message(error_code);
}
#ifndef LIBARGON2_H
#define LIBARGON2_H

#include "argon2.h"

#ifdef LIBARGON2_EXPORTS
#define LIBARGON2_DLLEXPORT __declspec(dllexport)
#else
#define LIBARGON2_DLLEXPORT __declspec(dllimport)
#endif

/**
* This file is simply to proxy the argon2 functions so that I export with dllexport
* without modifying the original argon2.h header
*/

/**
* Hashes a password with Argon2i or ARgon2d, producing a raw hash by allocating memory at
* @hash
* @param t_cost Number of iterations
* @param m_cost Sets memory usage to m_cost kibibytes
* @param parallelism Number of threads and compute lanes
* @param pwd Pointer to password
* @param pwdlen Password size in bytes
* @param salt Pointer to salt
* @param saltlen Salt size in bytes
* @param hash Buffer where to write the raw hash - updated by the function
* @param hashlen Desired length of the hash in bytes
* @pre   Different parallelism levels will give different results
* @pre   Returns ARGON2_OK if successful
*/
LIBARGON2_DLLEXPORT int crypto_argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
	const uint32_t parallelism, const void *pwd,
	const size_t pwdlen, const void *salt,
	const size_t saltlen, void *hash,
	const size_t hashlen, char *encoded,
	const size_t encodedlen, argon2_type type);

/**
* Verifies a password against an encoded string
* Encoded string is restricted as in validate_inputs()
* @param encoded String encoding parameters, salt, hash
* @param pwd Pointer to password
* @pre   Returns ARGON2_OK if successful
*/
LIBARGON2_DLLEXPORT int crypto_argon2_verify(const char *encoded, const void *pwd,
	const size_t pwdlen, argon2_type type);

/**
* Get the associated error message for given error code
* @return  The error message associated with the given error code
*/
LIBARGON2_DLLEXPORT const char *crypto_argon2_error_message(int error_code);

#endif
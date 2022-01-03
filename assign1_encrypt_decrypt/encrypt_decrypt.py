#!/usr/bin/env python3

##### IMPORTS

import argparse
import os
import hashlib

from collections.abc import Callable

from multiprocessing import Pool
from os import cpu_count

from sys import exit, stdout

from time import time_ns
from typing import Iterator, Mapping, Optional, Union

# add any additional modules you need here

##### METHODS


def block_idx(block_size: int, offset: int = 0) -> Iterator[bytes]:
    """A generator for creating an arbitrary number of block indicies.

    PARAMETERS
    ==========
    block_size: The size of block to use, in bytes. Determines the maximum number
      of blocks returned, as well.
    offset: The number this generator will start counting from. Defaults to zero.

    YIELDS
    ======
    Successive block indicies.
    """

    mask = (1 << (block_size * 8)) - 1  # set an upper limit AND bitmask
    idx = 0
    while idx <= mask:

        # adding the offset is slower, but the bookkeeping is easier
        yield ((idx + offset) & mask).to_bytes(block_size, "big")
        idx += 1


def generate_iv(length: int) -> bytes:
    """Generate an initialization vector for encryption. Must be drawn from a
    cryptographically-secure pseudo-random number generator.

    PARAMETERS
    ==========
    length: The length of the IV desired, in bytes.

    RETURNS
    =======
    A bytes object containing the IV.
    """
    assert type(length) is int

    return os.urandom(length)


class Hasher:
    """Encapsulates the hash function used for encryption. This is written as a
    class so that we have easy access to both the hash and hash's block size.

    EXAMPLES:

    > h = Hasher()
    > print( h.digest_size )
    32
    > h.hash( b'test value' )
    b'a byte object 32 characters long'

    """

    def __init__(self):
        """Create a Hasher. This mostly exists to put the block size in place."""

        # the size of the output of the hash function
        self.digest_size = 32

        # Uncomment the following line of code and substitute the hash's ideal input
        #  block size. IMPORTANT: this is almost never the same size as the digest size!

        self.block_size = 64

        self.block_bytes = 32  # TODO check this

    def hash(self, data: bytes) -> bytes:
        """Hash an arbitrary number of bytes into a 32-byte output. Hopefully this is
        done in a cryptographically-secure way.

        PARAMETERS
        ==========
        data: The bytes object to be hashed.

        RETURNS
        =======
        A bytes object containing 32 bytes of hash value.
        """
        assert type(data) is bytes

        h = hashlib.sha256()
        h.update(data)
        return h.digest()


def xor(a: bytes, b: bytes) -> bytes:
    """Bit-wise exclusive-or two byte sequences. If the two bytes objects differ in
    length, pad with zeros.

    PARAMETERS
    ==========
    a, b: bytes objects to be XORed together.

    RETURNS
    =======
    A bytes object containing the results.
    """
    assert type(a) is bytes
    assert type(b) is bytes

    if len(a) > len(b):
        b = b + b"\x00" * (len(a) - len(b))

    elif len(a) < len(b):
        a = a + b"\x00" * (len(b) - len(a))

    return bytes(x ^ y for x, y in zip(a, b))


def HMAC(data: bytes, key: bytes, hasher: Hasher) -> bytes:
    """Perform HMAC with the given hash function. Be sure to read the HMAC spec carefully!

    PARAMETERS
    ==========
    data:   The bytes object to be hashed.
    key:    A bytes object to be used as a key.
    hasher: A Hasher instance.

    RETURNS
    =======
    A bytes object containing the digest.
    """
    assert type(data) is bytes
    assert type(key) is bytes

    if len(key) > hasher.block_size:
        L = hasher.hash(key)
        padded_key = L + b"\x00" * (hasher.block_size - len(L))
    elif len(key) < hasher.block_size:
        padded_key = key + b"\x00" * (hasher.block_size - len(key))
    elif len(key) == hasher.block_size:
        padded_key = key

    ipad = b"\x36" * hasher.block_size
    opad = b"\x5c" * hasher.block_size

    ipad_xor = xor(padded_key, ipad)
    inner = ipad_xor + data
    inner_hash = hasher.hash(inner)

    opad_xor = xor(padded_key, opad)
    outer = opad_xor + inner_hash
    outer_hash = hasher.hash(outer)

    return outer_hash


def pad(data: bytes, digest_size: int) -> bytes:
    """Pad out the given bytes object with PKCS7 so it fits within the given
    digest size. That size is guaranteed to be 255 bytes or less.

    PARAMETERS
    ==========
    data:        The bytes object to be padded.
    digest_size: The output length in bytes is 0 mod digest_size.

    RETURNS
    =======
    A bytes object containing the padded value.
    """
    assert type(data) is bytes
    assert type(digest_size) is int
    assert (digest_size > 1) and (digest_size < 256)

    padding = (digest_size - len(data)) % digest_size

    if padding == 0:
        padding = digest_size

    pkcs7 = (chr(padding) * padding).encode()

    padded_value = data + pkcs7

    return padded_value
    # TODO citation https://laconicwolf.com/2018/12/02/cryptopals-challenge-9-implement-pkcs7-padding-in-python/


def unpad(data: bytes) -> Optional[bytes]:
    """Remove PKCS7 from the given bytes object.

    PARAMETERS
    ==========
    data:       The bytes object to have any padding removed.

    RETURNS
    =======
    Either a bytes object containing the original value, or None if
      no valid padding was found.
    """
    assert type(data) is bytes

    data_array = bytearray(data)
    padding_value = data_array[-1:]
    padding_size = int.from_bytes(padding_value, "big")

    while padding_size > 0:
        if data_array[-1:] != padding_value:
            return None
        else:
            del data_array[-1:]
            padding_size -= 1

    return bytes(data_array)


def encrypt(
    iv: bytes,
    data: bytes,
    key: bytes,
    hasher: Hasher,
    block_ids: Callable[[int], Iterator[bytes]],
) -> bytes:
    """Encrypt the given data, with the given IV and key, using the given hash function.
    Assumes the data has already been padded to align with the digest size. Do not
    prepend the IV. The IV must have the same length as the hash function's block size.

    PARAMETERS
    ==========
    iv:        The initialization vector used to boost semantic security
    data:      The padded data to be encrypted.
    key:       A bytes object to be used as a key.
    hasher:    A Hasher instance.
    block_ids: A generator that generates block indexes of a specific size.
         (see block_idx())

    RETURNS
    =======
    A bytes object containing the encrypted value. Note that the return is not a list or
      generator.
    """
    assert type(iv) is bytes
    assert type(key) is bytes
    assert type(data) is bytes
    assert (len(data) % hasher.digest_size) == 0
    assert len(iv) == hasher.block_size

    digest_size = hasher.digest_size
    generator = block_ids(hasher.block_size)
    plaintext_block = [
        data[i : i + digest_size] for i in range(0, len(data), digest_size)
    ]
    encrypted_data = b""

    for each in plaintext_block:
        next_block_id = next(generator)
        block_ID_IV = xor(HMAC(xor(next_block_id, iv), key, hasher), each)
        encrypted_data += block_ID_IV
    return encrypted_data


def pad_encrypt_then_HMAC(
    plaintext: bytes,
    key_cypher: bytes,
    key_HMAC: bytes,
    hasher: Hasher,
    block_ids: Callable[[int], Iterator[bytes]],
) -> bytes:
    """Encrypt a plaintext with your encryption function. Note the order of operations!

    PARAMETERS
    ==========
    plaintext: The bytes object to be encrypted. Not necessarily padded!
    key_cypher: The bytes object used as a key to encrypt the plaintext.
    key_HMAC: The bytes object used as a key for the keyed-hash MAC.
    hasher: A Hasher instance.
    block_ids: A generator that generates block indexes of a specific size.
         (see block_idx())

    RETURNS
    =======
    The cyphertext, as a bytes object. Note that the return is not a list or
      generator.
    """

    assert type(plaintext) is bytes
    assert type(key_cypher) is bytes
    assert type(key_HMAC) is bytes

    iv = generate_iv(hasher.block_size)
    data = pad(plaintext, hasher.digest_size)
    encrypted_data = encrypt(iv, data, key_cypher, hasher, block_ids)
    iv_ciphertext = iv + encrypted_data
    pad_then_HMAC = iv_ciphertext + HMAC(iv_ciphertext, key_HMAC, hasher)
    return pad_then_HMAC


def decrypt_and_verify(
    cyphertext: bytes,
    key_cypher: bytes,
    key_HMAC: bytes,
    hasher: Hasher,
    block_ids: Callable[[int], Iterator[bytes]],
) -> Optional[bytes]:
    """Decrypt a plaintext that had been encrypted with the prior function.
    Also performs integrity checking to help ensure the original wasn't
    corrupted.

    PARAMETERS
    ==========
    cyphertext: The bytes object to be decrypted
    key_cypher: The bytes object used as a key to decrypt the plaintext.
    key_HMAC: The bytes object used as a key for the keyed-hash MAC.
    hasher: A Hasher instance.
    block_ids: A generator that generates block indexes of a specific size.
         (see block_idx())

    RETURNS
    =======
    If the cyphertext could be decrypted and validates, this returns a bytes
      object containing the plaintext. Otherwise, it returns None.
    """

    assert type(cyphertext) is bytes
    assert type(key_cypher) is bytes
    assert type(key_HMAC) is bytes


##### MAIN

if __name__ == "__main__":

    # parse the command line args
    cmdline = argparse.ArgumentParser(description="Encrypt or decrypt a file.")

    methods = cmdline.add_argument_group(
        "ACTIONS", "The three actions this program can do."
    )

    methods.add_argument(
        "--decrypt",
        metavar="FILE",
        type=argparse.FileType("rb", 0),
        help="A file to be decrypted.",
    )
    methods.add_argument(
        "--encrypt",
        metavar="FILE",
        type=argparse.FileType("rb", 0),
        help="A file to be encrypted.",
    )
    methods.add_argument(
        "--dump",
        action="store_true",
        help="Dump a binary stream generated by the hash function to stdout. Handy for testing its quality.",
    )

    methods = cmdline.add_argument_group(
        "OPTIONS", "Modify the defaults used for the above actions."
    )

    methods.add_argument(
        "--output",
        metavar="OUTPUT",
        type=argparse.FileType("wb", 0),
        help="The output file. If omitted, print the decrypted plaintext or dump to stdout. The destination's contents are wiped, even on error.",
    )
    methods.add_argument(
        "--password",
        metavar="PASSWORD",
        type=str,
        default="swordfish",
        help="The password to use as a key.",
    )
    methods.add_argument(
        "--reference",
        metavar="FILE",
        type=argparse.FileType("rb", 0),
        help="If provided, check the output matches what is in this file.",
    )
    methods.add_argument(
        "--threads",
        type=int,
        default=0,
        help="Number of threads to use with dump. Numbers < 1 implies all available.",
    )

    methods.add_argument(
        "--offset",
        type=int,
        default=0,
        help="An offset into the sequence used during dump.",
    )

    args = cmdline.parse_args()

    if args.threads < 1:
        args.threads = cpu_count()

    if args.offset < 0:
        args.offset *= -1

    h = Hasher()

    # which mode are we in?
    if args.decrypt:

        # hash the key to obscure it, then split that into two derived keys
        key = h.hash(args.password.encode("utf-8"))
        key_enc = key[: len(key) >> 1]
        key_HMAC = key[len(key) >> 1 :]

        plaintext = decrypt_and_verify(
            args.decrypt.read(), key_enc, key_HMAC, h, block_idx
        )
        args.decrypt.close()

        if plaintext is None:
            print("ERROR: Could not decrypt the file!")
            exit(1)

        if args.reference:
            ref = args.reference.read()
            if ref != plaintext:
                print("ERROR: The output and reference did not match!")
                exit(2)

        if args.output:
            args.output.write(plaintext)
            args.output.close()

        else:
            try:
                print(plaintext.decode("utf-8"))
            except UnicodeError as e:
                print(
                    "WARNING: Could not print out the encrypted contents. Was it UTF-8 encoded?"
                )
                exit(3)

    elif args.encrypt:

        key = h.hash(args.password.encode("utf-8"))
        key_enc = key[: len(key) >> 1]
        key_HMAC = key[len(key) >> 1 :]

        cyphertext = pad_encrypt_then_HMAC(
            args.encrypt.read(), key_enc, key_HMAC, h, block_idx
        )

        if args.reference:
            ref = args.reference.read()
            if ref != cyphertext:
                print("ERROR: The output and reference did not match!")
                exit(4)

        if args.output:
            args.output.write(cyphertext)
            args.output.close()

        else:
            print("As the cyphertext is binary, it will not be printed to stdout.")

    elif args.dump:

        generator = block_idx(h.block_size, args.offset)
        with Pool(args.threads) as p:
            for output in p.imap(h.hash, generator, 64):
                if args.output:
                    args.output.write(output)
                else:
                    stdout.buffer.write(output)

    # another approach to do the same:
    #        for input in generator:
    #                stdout.buffer.write( h.hash(input) )

    else:

        print("Please select one of encryption, decryption, or dumping.")

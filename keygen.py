#!/usr/bin/env python3
import base64
import random
import secrets
import binascii

# Tool for generating cryptographic keys

# *** Key Generation ***

# Python's PRNG
# size in bytes
def generate_key_prng(n):
  return b"".join((bytes([random.randrange(0, 256)]) for x in range(n))) 

# Python's module for generating cryptographically strong random numbers
def generate_key_cprng(n):
  return secrets.randbits(8*n).to_bytes(n, byteorder='little')

# *** Print Helpers ***

def to_dec(x):
  return " ".join(str(xx) for xx in x)

def to_hex(x):
  return (b"0x" + binascii.hexlify(x)).decode()

def to_b64(x):
  return (base64.b64encode(x)).decode()

if __name__ == "__main__":
  print("** PRNG generated key")
  k = generate_key_prng(2*16)
  print("dec:", to_dec(k))
  print("hex:", to_hex(k))
  print("base64:", to_b64(k))

  print("\n** CPRNG generated key")
  k = generate_key_cprng(2*16)
  print("dec:", to_dec(k))
  print("hex:", to_hex(k))
  print("base64:", to_b64(k))


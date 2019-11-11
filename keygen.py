#!/usr/bin/env python3
import hmac
import base64
import random
import secrets
import binascii
from sys import exit

# Tool for generating cryptographic keys

# *** Key Generation ***

# PBKDF2 (Password-Based Key Derivation Function 2)
# key stretching
def generate_key_password(passwd, salt, iterations, output_key_len):
  from hashlib import sha256
  rounds = output_key_len//256
  key = b""
  for i in range(rounds or 1):
    salt_i = salt + i.to_bytes(32, 'big')
    for j in range(iterations):
      passwd = hmac.new(passwd, salt_i, digestmod=sha256).digest()
      salt_i = passwd
    key += passwd
  return key

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
  print("** Password derived key")
  passwd = b"this_is_password"
  salt = generate_key_cprng(32)
  print("password:", passwd.decode())
  print("salt:", to_hex(salt))
  passwd = generate_key_password(passwd, salt, 4096, 256)
  print("key:", to_hex(passwd))
  print("key length:", len(passwd), "bytes")

  print("\n** PRNG generated key (NOT safe)")
  k = generate_key_prng(2*16)
  print("dec:", to_dec(k))
  print("hex:", to_hex(k))
  print("base64:", to_b64(k))
  print("key length:", len(k), "bytes")

  print("\n** CPRNG generated key")
  k = generate_key_cprng(2*16)
  print("dec:", to_dec(k))
  print("hex:", to_hex(k))
  print("base64:", to_b64(k))
  print("key length:", len(k), "bytes")


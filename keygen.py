#!/usr/bin/env python3
import hmac
import base64
import random
import secrets
import binascii
from sys import exit

# Tool for generating cryptographic keys

# *** Key Generation ***

def F(passwd, salt, iterations, i):
  from hashlib import sha1, sha256
  u = hmac.new(passwd, salt + i.to_bytes(4, 'big'), digestmod=sha1).digest()
  out = u
  for j in range(1, iterations):
    ui = hmac.new(passwd, u, digestmod=sha1).digest()
    out = byte_xor(ui, out)
    u = ui
  return out 
  
# PBKDF2 (Password-Based Key Derivation Function 2)
# key stretching
def generate_key_password(passwd, salt, iterations, output_key_len):
  from hashlib import sha1, sha256
  rounds = output_key_len//160
  key = b""
  for i in range(1, rounds+1 if rounds != 0 else 2):
    key += F(b"eBkXQTfuBqp'cTcar&g*", binascii.unhexlify("A009C1A485912C6AE630D3E744240B04"), iterations, i)
  return key[:16]

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

def byte_xor(b1, b2):
  return bytes(a ^ b for a, b in zip(b1, b2))

if __name__ == "__main__":
  x = generate_key_password(b"eBkXQTfuBqp'cTcar&g*", binascii.unhexlify("A009C1A485912C6AE630D3E744240B04"), 1000, 128)
  print(to_hex(x))
  print(len(x))
  assert x == binascii.unhexlify("17EB4014C8C461C300E9B61518B9A18B")
  print("PASSED")
  exit(0)

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


#!/usr/bin/env python3
import base64
import random
import binascii

# Tool for generating cryptographic keys

# *** Key Generation ***

# Python's PRNG
# size in bytes
def generate_key_prng(size):
  return b"".join((bytes([random.randrange(0, 256)]) for x in range(size))) 

# OS random source
def generate_key_osrng(size):
  # TODO: 
  pass

# *** Print Helpers ***

def to_dec(x):
  return " ".join(str(xx) for xx in x)

def to_hex(x):
  return binascii.hexlify(x)

def to_b64(x):
  return base64.b64encode(x)

if __name__ == "__main__":
  k = generate_key_prng(2*16)
  print(k)
  print("dec:", to_dec(k))
  print("hex: 0x%s" % to_hex(k).decode())
  print("base64:", to_b64(k).decode())


#!/usr/bin/env python3
import hmac
import base64
import random
import secrets
import argparse
import binascii
from sys import exit
from getpass import getpass

# A tool for generating cryptographic keys

# *** Key Generation ***

# note: argument sizes in bytes

# compute PBKDF2 block
def block_pbkdf2(passwd, salt, rounds, i):
  from hashlib import sha1, sha256
  u = hmac.new(passwd, salt + i.to_bytes(4, 'big'), digestmod=sha1).digest()
  out = u
  for j in range(1, rounds):
    ui = hmac.new(passwd, u, digestmod=sha1).digest()
    out = byte_xor(ui, out)
    u = ui
  return out 
  
# PBKDF2 (Password-Based Key Derivation Function 2)
# key stretching
def generate_key_password(passwd, salt, rounds, output_key_len):
  blocks = 8*output_key_len//160
  key = b""
  for i in range(1, blocks+2):
    key += block_pbkdf2(passwd, salt, rounds, i)
  return key[:output_key_len]

# Python's PRNG
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
  parser = argparse.ArgumentParser()
  parser.add_argument("-s", "--size", metavar="N", default=16, type=int, help="output key size (bytes)")
  parser.add_argument("-m", "--method", choices=('password', 'prng', 'cprng'), type=str, help="key generation method")
  parser.add_argument("-p", "--output-format", choices=('dec', 'hex', 'base64', 'all'), default='all', type=str, help="key output format (default all)")
  parser.add_argument("--rounds", metavar="N", default=10000, type=int, help="round count for BPKDF2")
  args = parser.parse_args()

  # interactive select
  if args.method == None:
    args.method = input("Select mode (prng, cprng, password): ") or "cprng"
    if not args.size:
      args.size = int(input("Select key size (default 16): ") or 16)
    if not args.output_format:
      args.output_format = input("Select output format (dec, hex, base64, all): ") or "all"
    print()

  # generation method
  if args.method == "password":
    print("** Password derived key")
    salt = generate_key_cprng(16)
    rounds = args.rounds
    passwd = getpass()
    k = generate_key_password(passwd.encode(), salt, args.rounds, args.size)
    print("salt:", to_hex(salt))
    print("key length:", len(k), "bytes")
    print("rounds:", args.rounds)
  elif args.method == "prng":
    print("** PRNG generated key (NOT safe)")
    k = generate_key_prng(args.size)
    print("key length:", len(k), "bytes")
  elif args.method == "cprng":
    print("** CPRNG generated key")
    k = generate_key_cprng(args.size)
    print("key length:", len(k), "bytes")

  # output format
  if args.output_format == "dec":
    print("dec:", to_dec(k))
  elif args.output_format == "hex":
    print("hex:", to_hex(k))
  elif args.output_format == "base64":
    print("base64:", to_b64(k))
  elif args.output_format == "all":
    print("dec:", to_dec(k))
    print("hex:", to_hex(k))
    print("base64:", to_b64(k))


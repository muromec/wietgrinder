import struct
from sbox import sbox_lookup

def ror(value, bits):
  low = (value >> bits) & 0xFF_FF_FF_FF
  high = (value << (32 - bits)) & 0xFF_FF_FF_FF
  return low | high

def ubfx(value, lsb, width):
  return (value >> lsb) & ((1 << width) -1)

assert ror(0xDEAD_BEAF, 16) == 0xBEAF_DEAD 

def sbox_pass(byte1, byte2):
  bb0 = ubfx(byte1, 2, 6)
  bb1 = ubfx(byte1, 10, 6)
  bb2 = ubfx(byte1, 18, 6)
  bb3 = byte1 >> 26

  bb0 = sbox_lookup(0, bb0)
  bb1 = sbox_lookup(2, bb1)
  bb2 = sbox_lookup(4, bb2)
  bb3 = sbox_lookup(6, bb3)

  bc0 = ubfx(byte2, 2, 6)
  bc1 = ubfx(byte2, 10, 6)
  bc2 = ubfx(byte2, 18, 6)
  bc3 = byte2 >> 26

  bc0 = sbox_lookup(1, bc0)
  bc1 = sbox_lookup(3, bc1)
  bc2 = sbox_lookup(5, bc2)
  bc3 = sbox_lookup(7, bc3)

  return bb0 ^ bb1 ^ bb2 ^ bb3 ^ bc1 ^ bc2 ^ bc3 ^ bc0


def feistel_round(next_l, next_r, key, key_idx):
  left, right = struct.unpack_from('<II', key, key_idx)
  left = left ^ next_l
  right = right ^ next_l
  next_r = next_r ^ sbox_pass(left, ror(right, 4))

  left, right = struct.unpack_from('<II', key, key_idx + 8)
  left = left ^ next_r
  right = right ^ next_r
  next_l = sbox_pass(left, ror(right, 4)) ^ next_l

  return (next_l, next_r)

def prepare(half_r, half_l):
  
  mixed_halfs = (half_r) ^ (half_l >> 4)

  w001 = 0x0F0F_0F0F & mixed_halfs
  w002 = w001 ^ half_r
  w003 = 0xFF_FF_FF_FF & (half_l ^ (w001 << 4))
  w004 = w003 ^ w002 >> 16
  w005 = w004 & 0xFFFF
  w006 = w002 ^ ((w005 << 16) & 0xFFFF0000)
  w007 = w005 ^ w003
  w008 = 0x33333333 & (w006 ^ w007 >> 2)
  w009 = w008 ^ w006
  w010 = 0xFFFF_FFFF & (w007 ^ (w008 << 2))
  w011 = 0x00_FF_00_FF & (w010 ^ (w009 >> 8))
  w012 = w011 ^ w010
  w013 = 0xFFFF_FFFF & (w009 ^ (w011  << 8))
  w014 = 0x5555_5555 & (w013 ^ (w012 >> 1))
  w015 = 0xFFFF_FFFF & (w014 << 1)


  r = ror(w014 ^ w013, 29)
  l = ror(w015 ^ w012, 29)

  return r, l


def finalize(next_r, next_l):
  w001 = ror(next_r, 3)
  w002 = ror(next_l, 3)
  w003 = 0x55555555 & ((w002 >> 1) ^ w001)
  w004 = w003 ^ w001
  w005 = (w003 << 1) & 0xFF_FF_FF_FF
  w006 = w005 ^ w002
  w007 = 0x00ff_00ff & (w006 ^ (w004 >> 8))
  w008 = w007 ^ w006
  w009 = 0xFFFF_FFFF & (w004 ^ (w007 << 8))
  w010 = 0x3333_3333 & (w009 ^ (w008  >> 2))
  w011 = w010 ^ w009
  w012 = w008 ^ (w010 << 2) & 0xFFFF_FFFF
  w013 = w012 ^ w011 >> 16
  w014 = w013 & 0xffff
  w015 = w014 ^ w012
  w016 = w011 ^ ((w014 << 16) & 0xFF_FF_00_00)
  w017 = 0xf0f0f0f & (w016 ^ w015 >> 4)

  r = w017 ^ w016
  l = w015 ^ (w017 << 4) & 0xFFFF_FFFF

  return r, l


def encrypt_block(block, key):
  key_offset = 0
  key_len = len(key)
  assert (key_len % 16) == 0
  assert len(block) == 8

  clear_r, clear_l = struct.unpack_from('<II', block, 0)
  next_l, next_r = prepare(clear_r, clear_l)

  while key_offset < key_len:
    next_l, next_r = feistel_round(next_l, next_r, key, key_offset)
    key_offset += 16

  next_r, next_l = finalize(next_r, next_l)
  return struct.pack('<II', next_r, next_l)

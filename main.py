import struct
from sbox import sbox_lookup
from algo import encrypt_block
from test_data import test_data

def generate_cleartext(challenge):
  cleartext = bytearray([
    0x00, 0x00, 0x00, 0x00, 0xf1, 0x69, 0x82, 0x59,
    0x76, 0x1f, 0x17, 0x14, 0x77, 0x48, 0x36, 0xf7,
    0x58, 0x27, 0x66, 0x59, 0xf9, 0x08, 0x93, 0x21,
    0x95, 0xf9, 0x59, 0x52, 0x41, 0x52, 0xf8, 0x95,
    0x69, 0x43, 0x81, 0xf9, 0x42, 0x89, 0x13, 0x15,
    0xf8, 0x58, 0x80, 0x91, 0x37, 0xf9, 0x59, 0x98,
    0x44, 0x33, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]);

  for pos, digit in enumerate(challenge):
    off = 0 if pos % 2 else 4
    cleartext[int(pos/2)] = cleartext[int(pos/2)] | (int(digit) << off)
  return cleartext


def main(challenge, seq, key):
  key = bytes.fromhex(key)
  cleartext = generate_cleartext(challenge)
  ciphertext = bytearray([])
  seq_code = int(seq, 16)

  prev_block = [0] * 8
  for pos in range(0, len(cleartext), 8):
    block = bytearray([
      cleartext[block_pos] ^ prev_block[block_pos % 8]
      for block_pos in range(pos, pos + 8)
    ])

    prev_block = encrypt_block(block, key)
    ciphertext += prev_block

  (code,) = struct.unpack_from('>I', ciphertext, 48)
  return ('code: {:04x}{:08x}'.format(seq_code, code))

def run_tests():
  cb = bytes([0, 1, 2, 3, 4, 5, 6, 7])
  test_key = bytes([
    0xFF & (i | i << 8) ^ 0x33
    for i in range(128)
  ])
  eb = encrypt_block(cb, test_key)
  assert eb.hex() == '976c9fdba18f2dc2'
  for [code, expected] in test_data:
    actual = main(str(code), '0x3EF', test_key.hex())
    assert actual == expected, f'E: {expected}'



if __name__ == "__main__":
    import sys
    if sys.argv[1] == 'test':
      sys.exit(0 if run_tests() else 1)
    
    if len(sys.argv) != 4:
      sys.stderr.write("""
Usage: wietgrinder number seq key

  number is a decimal number (8 digits)
  seq is a hex number
  key is a hex string length of 128 bytes

""")
      sys.exit(1)
    out = main(sys.argv[1], sys.argv[2], sys.argv[3])
    print(out)

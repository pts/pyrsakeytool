#! /bin/sh
# by pts@fazekas.hu at Sat Apr 25 01:21:50 CEST 2020

""":" # rsakeytool.py: Convert between various RSA private key formats.

type python    >/dev/null 2>&1 && exec python    -- "$0" ${1+"$@"}
type python3   >/dev/null 2>&1 && exec python3   -- "$0" ${1+"$@"}
type python2.7 >/dev/null 2>&1 && exec python2.7 -- "$0" ${1+"$@"}
type python2.6 >/dev/null 2>&1 && exec python2.6 -- "$0" ${1+"$@"}
type python2.5 >/dev/null 2>&1 && exec python2.5 -- "$0" ${1+"$@"}
type python2.4 >/dev/null 2>&1 && exec python2.4 -- "$0" ${1+"$@"}
exec python -- ${1+"$@"}; exit 1  # Just for the error message.

This script needs Python 2.4, 2.5, 2.6, 2.7 or 3.x.

See usage on https://github.com/pts/pyrsakeytool

TODO(pts): Add input support for format='gpg'.
TODO(pts): Add command-line parsing compatible with ssh-keygen.
TODO(pts): Add output format='gpgascii', 'gpgpublicascii'.
TODO(pts): Read 2 private keys from GPG (.lst), write 2 public keys.
TODO(pts): Add input format='dict', reverse of portable_repr.
"""

import binascii
import struct


# -- Python 2.x and 3.x compatibility for strings.


try:
  bytes
except NameError:
  bytes = str


if bytes is str:  # Python 2.x.
  bb = aa = str
  def aa_strict(data):
    # Fails for bytes with code >127.
    return data.decode('ascii').encode('ascii')
else:  # Python 3.x.
  def bb(data):
    return bytes(data, 'ascii')
  def aa(data):
    return str(data, 'ascii')
  def aa_strict(data):
    return str(data, 'ascii')


bbe = bb('')
bbnl = bb('\n')
bbz = bb('\0')


# -- Python 2.x and 3.x compatibility for integers.


try:
  long
  integer_types = (int, long)
except NameError:
  integer_types = (int,)

if getattr(0, 'to_bytes', None):  # Python 3.2--. Faster than below.
  def uint_to_any_be(value, is_low=False, is_hex=False):
    if value < 0:
      raise ValueError('Bad negative uint.')
    bitsize = value.bit_length() or 1
    if is_low:  # Prepend a bb('\0') to values with high 7 bit set.
      size = (bitsize >> 3) + 1
    else:
      size = (bitsize + 7) >> 3
    value = value.to_bytes(size, 'big')
    if is_hex:
      return binascii.hexlify(value)
    return value
else:
  def uint_to_any_be(value, is_low=False, is_hex=False,
                      _bbz=bbz, _bb0=bb('0'), _bb8=bb('8'), _bb00=bb('00'), _is_hex_bytes=isinstance(hex(0), bytes)):
    if value < 0:
      raise ValueError('Bad negative uint.')
    if _is_hex_bytes:
      # In Python 2.4--2.7, '%x' % value is 4.327% slower than hex(value)[2:], but
      # ('%x' % value).rstrip('L') and variants are slower than either.
      value = '%x' % value
    else:
      # In Python 3.5--, b'%x' % value is 3.185% faster than bytes(hex(value)[2:], 'ascii').
      value = bytes(hex(value), 'ascii')[2:]
    if len(value) & 1:
      value = _bb0 + value
    elif is_low and not _bb0 <= value[:1] < _bb8:
      value = _bb00 + value
    if is_hex:
      return value
    return binascii.unhexlify(value)


if getattr(0, 'from_bytes', None):
  def uint_from_be(v, _from_bytes=int.from_bytes):  # Python >=3.2. Not in six.
    return _from_bytes(v, 'big')
else:
  def uint_from_be(data, _hexlify=binascii.hexlify):  # Not in six.
    data = _hexlify(data)
    if data:
      return int(data, 16)
    return 0


if getattr(0, 'bit_length', None):  # Python 2.7, Python 3.1--.
  def get_uint_byte_size(value):
    if value < 0:
      raise ValueError('Negative uint for byte size.')
    return ((value.bit_length() or 1) + 7) >> 3
else:
  def get_uint_byte_size(value):
    if value < 0:
      raise ValueError('Negative uint for byte size.')
    # hex(value) is 1.361 times faster than '%x' % value on Python 2.4.
    # hex(value) is 2.130 times faster than '%x' % value on Python 3.0.
    value = hex(value)
    return (len(value) - (1 + (value.endswith('L')))) >> 1


if getattr(0, 'bit_length', None):  # Python 2.7, Python 3.1--.
  def get_uint_bitsize(value):
    if value < 0:
      raise ValueError('Negative uint for bitsize.')
    return value.bit_length() or 1
else:
  def get_uint_bitsize(value, _octdigit_bitcount={'0': -3, '1': -3, '2': -2, '3': -2, '4': -1, '5': -1, '6': -1, '7': -1}):
    if value < 0:
      raise ValueError('Negative uint for bitsize.')
    # hex(value) is 1.361 times faster than '%x' % value on Python 2.4.
    # hex(value) is 2.130 times faster than '%x' % value on Python 3.0.
    value = hex(value)
    result = (len(value) - (2 + (value.endswith('L')))) << 2
    return result + _octdigit_bitcount.get(value[2 : 3], 0)


# -- Python 2.x and 3.x compatibility for iterators.

if isinstance(zip(), list):
  from itertools import izip
else:
  izip = zip

if not isinstance(range(0), list):
  xrange = range  # Python 3.x doesn't have xrange.

# --- ASN.1 DER and PEM.


def der_field(xtype, args, _bbe=bbe):
  output = [_bbe, _bbe]
  if isinstance(args, bytes):
    args = (args,)
  elif not isinstance(args, (tuple, list)):
    args = tuple(args)
  size = sum(len(arg) for arg in args)
  for arg in args:
    if not isinstance(arg, bytes):
      raise TypeError
    output.append(arg)
  # https://github.com/etingof/pyasn1/blob/db8f1a7930c6b5826357646746337dafc983f953/pyasn1/codec/ber/encoder.py#L53
  if size < 0x80:
    output[0] = struct.pack('>BB', xtype, size)
  elif size >> (0x7e << 3):
    raise ValueError('DER field too long.')
  else:
    output[1] = uint_to_any_be(size)
    output[0] = struct.pack('>BB', xtype, 0x80 | len(output[1]))
  return _bbe.join(output)


def der_oid(value):
  # https://github.com/etingof/pyasn1/blob/db8f1a7930c6b5826357646746337dafc983f953/pyasn1/codec/ber/encoder.py#L296
  value = tuple(map(int, value.split('.')))
  if len(value) < 2:
    raise ValueError('OID too short.')
  if [1 for item in value if item < 0]:
    raise ValueError('Negative value in OID.')
  if value[0] > 2:
    raise ValueError('Bad value[0] in OID.')
  if ((value[0] in (0, 1) and value[1] >= 40) or
       value[0] == 2 and value[1] > 175):
    raise ValueError('Bad value[1] in OID.')
  output = [struct.pack('>B', value[0] * 40 + value[1])]
  for item in value[2:]:
    if item < 0x80:
      output.append(struct.pack('>B', item))
    else:
      xs = []
      while item:
        xs.append(0x80 | item & 0x7f)
        item >>= 7
      xs[0] &= 0x7f
      while xs:
        output.append(struct.pack('>B', xs.pop()))
  return der_field(6, output)


assert binascii.hexlify(der_oid('1.2.840.113549.1.1.1')) == bb('06092a864886f70d010101')


def der_bytes(value):
  return der_field(4, value)


def der_bytes_bit(value):
  return der_field(3, value)


def der_value(value, _bb50=bb('\5\0')):  # Similar to ASN.1 BER and CER.
  # https://en.wikipedia.org/wiki/X.690#DER_encoding
  # DER has a unique encoding for each value.
  if isinstance(value, integer_types):
    return der_field(2, uint_to_any_be(value, is_low=True),)
  elif isinstance(value, tuple):
    return der_field(0x30, map(der_value, value))
  elif isinstance(value, bytes):
    return value
  elif value is None:
    return _bb50
  else:
    raise TypeError('Bad DER data type: %s' % type(value))


def parse_der_header(data, i, xtype, stype):
  if len(data) < i + 2:
    raise ValueError('EOF in der %s header.' % stype)
  b, size = struct.unpack('>BB', data[i : i + 2])
  if b != xtype:
    print [data[i : i + 10]]
    raise ValueError('Expected der %s.' % stype)
  i += 2
  if size < 0x80:
    return i, size
  elif size == 0x80:
    # We may want to apply size limit instead:
    # return i, len(data) - i
    raise ValueError('Unlimited der %s size.' % stype)
  elif size == 0xff:
    raise ValueError('Bad der %s size.' % stype)
  j, size = i + (size & 0x7f), 0
  while i != j:
    if len(data) <= i:
      raise ValueError('EOF in der %s size.' % stype)
    size = size << 8 | struct.unpack('>B', data[i : i + 1])[0]
    i += 1
  return i, size


def parse_der_sequence_header(data, i):
  return parse_der_header(data, i, xtype=0x30, stype='sequence')


def parse_der_bytes_header(data, i):
  return parse_der_header(data, i, xtype=4, stype='bytes')


def parse_der_zero(data, i, _bb210=bb('\2\1\0')):
  if len(data) < i + 3:
    raise ValueError('EOF in der zero.')
  if data[i : i + 3] != _bb210:
    assert 0, [data[:10], data[i : i + 10]]
    raise ValueError('Expected der zero.')
  return i + 3


def parse_der_uint(data, i, j=None):
  i, size = parse_der_header(data, i, xtype=2, stype='int')
  if j is not None and j < i + size:
    raise ValueError('EOF in size-limited der uint.')
  if size == 0:
    raise ValueError('Empty der uint.')
  if len(data) < i + size:
    raise ValueError('EOF in der uint.')
  if struct.unpack('>B', data[i : i + 1])[0] >= 0x80:
    raise ValueError('Negative der uint.')
  return i + size, uint_from_be(data[i : i + size])


def base64_encode(data, line_size=64, _bbnl=bbnl):
  data = binascii.b2a_base64(data).rstrip(_bbnl)
  if not isinstance(data, bytes):
    raise TypeError
  output, i = [], 0
  while i < len(data):
    output.append(data[i : i + line_size])  # base64.encodestring uses 76.
    i += line_size
  return _bbnl.join(output)


# --- Dropbear SSH and OpenSSH private key format.


def parse_be32size_uint(data, i, j=None):
  if j is not None and j < i + 4:
    raise ValueError('EOF in size-limited be32size uint size.')
  if len(data) < i + 4:
    raise ValueError('EOF in be32size uint size.')
  size, = struct.unpack('>L', data[i : i + 4])
  i += 4
  if j is not None and j < i + size:
    raise ValueError('EOF in size-limited be32size uint.')
  if len(data) < i + size:
    raise ValueError('EOF in be32size uint.')
  if size > 0 and struct.unpack('>B', data[i : i + 1])[0] >= 0x80:
    raise ValueError('Negative be32size uint.')
  return i + size, uint_from_be(data[i : i + size])


def parse_be32size_bytes(data, i, j=None):
  if j is not None and j < i + 4:
    raise ValueError('EOF in size-limited be32size bytes size.')
  if len(data) < i + 4:
    raise ValueError('EOF in be32size bytes size.')
  size, = struct.unpack('>L', data[i : i + 4])
  i += 4
  if j is not None and j < i + size:
    raise ValueError('EOF in size-limited be32size bytes.')
  if len(data) < i + size:
    raise ValueError('EOF in be32size uint.')
  return i + size, data[i : i + size]


def be32size_value(value):
  if isinstance(value, integer_types):
    data = uint_to_any_be(value, is_low=True)
  elif isinstance(value, bytes):
    data = value
  else:
    raise TypeError
  return struct.pack('>L', len(data)) + data


# --- Microsoft SSH private key format.


def parse_msblob_uint(data, i, j, size):
  if j is not None and j < i + size:
    raise ValueError('EOF in size-limited msblob uint.')
  if len(data) < i + size:
    raise ValueError('EOF in msblob uint.')
  return i + size, uint_from_be(data[i + size - 1 : i - 1 : -1])


# --- GPG 2.2 private key format.


def parse_gpg22_bytes(data, i, j=None, what='data', _bbcolon=bb(':')):
  if j is not None and i >= j:
    raise ValueError('EOF in size-limited gpg22 %s size.' % what)
  if i >= len(data):
    raise ValueError('EOF in gpg22 %s size.' % what)
  i0 = i
  while i < j and i < len(data) and data[i : i + 1].isdigit():
    i += 1
  if not (i < j and i < len(data) and data[i : i + 1] == _bbcolon):
    raise ValueError('Expected colon after gpg22 %s size.' % what)
  if i0 == i:
    raise ValueError('Empty gpg22 %s size.' % what)
  size = int(data[i0 : i])
  i += 1
  if j is not None and j < i + size:
    raise ValueError('EOF in size-limited gpg22 %s.' % what)
  if len(data) < i + size:
    raise ValueError('EOF in gpg22 %s.' % what)
  return i + size, i


def parse_gpg22_uint(data, i, j=None):
  i, i0 = parse_gpg22_bytes(data, i, j, 'uint')
  if i > i0 and struct.unpack('>B', data[i0 : i0 + 1])[0] >= 0x80:
    raise ValueError('Negative gpg22 uint.')
  return i, uint_from_be(data[i0 : i])


def append_gpg22_uint(output, prefix, value, _bbcolon=bb(':')):
  output.append(prefix)
  data = uint_to_any_be(value, True)
  output.append(bb(str(len(data))))
  output.append(_bbcolon)
  output.append(data)


# --- GPG 2.3 private key format.


def gpg23_uint(value):
  # This call is 2.779%..18.41% slower than a solution based on b('%x') %
  # value in Python 3.5--. We don't mind the small speed decrease.
  return binascii.hexlify(uint_to_any_be(value, True)).upper()


def parse_gpg23_uint(data, i, j, _bbhash=bb('#')):
  mj = min(j, len(data))
  if i >= mj:
    raise ValueError('EOF in gpg23 uint start.')
  if not (i < mj and data[i : i + 1] == _bbhash):
    raise ValueError('Bad gpg23 uint start.')
  i += 1
  if i >= mj:
    raise ValueError('EOF in gpg23 uint value start.')
  if struct.unpack('>B', data[i : i + 1])[0] >= 0x80:
    raise ValueError('Negative gpg23 uint.')
  i0 = i
  while i < mj and data[i : i + 1] != _bbhash:
    i += 1
  if i >= mj:
    raise ValueError('EOF in gpg23 uint.')
  if (i - i0) & 1:
    raise ValueError('Odd gpg23 uint size.')
  try:
    value = int(data[i0 : i], 16)
  except ValueError:
    value = None
  if value is None:
    raise ValueError('Bad gpg23 uint value.')
  return i + 1, value


# --- repr (Python literal expression) format tools.


BYTES_UNESCAPES = {bb('a'): bb('\a'), bb('b'): bb('\b'), bb('f'): bb('\f'), bb('n'): bb('\n'), bb('r'): bb('\r'), bb('t'): bb('\t'), bb('v'): bb('\v')}


def parse_repr_bytes(data, _bbqs=(bb('b\''), bb('b"')), _bbnl=bbnl, _bbbs=bb('\\'), _bbe=bbe, _bbxx=bb('xX'), _bb0123=bb('0123'),
                     _bbbsbs=bb('\\\\'), _bbr1=bb('\\x5c'), _bbr2=bb('\\\''), _bbr3=bb('\\x27'), _bbr4=bb('\\"'), _bbr5=bb('\\x22'),
                     _bytes_unescapes=BYTES_UNESCAPES):
  if not isinstance(data, bytes):
    raise TypeError
  prefix = data[:2].lower()
  if prefix not in _bbqs:
    raise ValueError('Not a bytes literal prefix.')
  if len(data) < 2 or not data.endswith(data[1 : 2]):
    raise ValueError('Not a bytes literal suffix.')
  # ast.literal_eval can't parse byte string literals in
  # Python 3.0, so we don't use it here.
  data = data[2 : -1]
  if _bbnl in data:
    raise ValueError('Found newline in bytes literal.')
  data = data.replace(_bbbsbs, _bbr1).replace(_bbr2, _bbr3).replace(_bbr4, _bbr5)
  if prefix[1:] in data:
    raise ValueError('Delimiter syntax error in bytes literal.')
  if _bbbs in data:  # Slow processing if contains backslash.
    i, size, output = 0, len(data), []
    while 1:
      i0, i = i, data.find(_bbbs, i)
      if i < 0:
        output.append(data[i0:])
        break
      if i + 1 >= size:
        raise ValueError('Trailing backslash in bytes literal.')
      if i > i0:
        output.append(data[i0 : i])
      c = data[i + 1 : i + 2]
      if c in _bbxx:  # We support \x?? only (not shorter).
        if i + 4 > size:
          raise ValueError('EOF in hex escape.')
        try:
          c = binascii.unhexlify(data[i + 2 : i + 4])
        except (ValueError, TypeError):
          c = None
        if c is None:
          raise ValueError('Bad hex escape.')
        i += 4
      elif c in _bb0123:  # We support \??? only (not shorter).
        if i + 4 > size:
          raise ValueError('EOF in oct escape.')
        try:
          c = struct.pack('>B', int(data[i + 1 : i + 4], 8))
        except ValueError:
          c = None
        if c is None:
          raise ValueError('Bad oct escape.')
        i += 4
      else:
        c = _bytes_unescapes.get(c)
        if not c:
          raise ValueError('Bad backslash escape: %r' % data[i : i + 1])
        i += 2
      output.append(c)
    data = _bbe.join(output)
  return data


def append_portable_repr(output, value,
                         _bbbools=(bb('False'), bb('True')), _bbnone=bb('None'), _bb0x=bb('0x'), _bbm0x=bb('-0x'), _bbop=bb('('), _bbcp=bb(')'), _bbcommasp=bb(', '),
                         _bbos=bb('['), _bbcs=bb(']'), _bbob=bb('{'), _bbcb=bb('}'), _bbcolonsp=bb(': '), _bbbs=bb('\\'), _bbsq=bb('\''), _bbb=bb('b')):
  if isinstance(value, bool):
    output.append(_bbbools[value])
  elif isinstance(value, integer_types):
    if value < 0:
      output.append(_bbm0x)
      output.append(uint_to_any_be(-value, is_hex=True))
    else:
      output.append(_bb0x)
      output.append(uint_to_any_be(value, is_hex=True))
  elif isinstance(value, bytes):
    value = repr(value)
    if value[:1] != 'b':
      output.append(_bbb)  # Force b prefix for Python 2.x repr.
    output.append(bb(value))
  elif value is None:
    output.append(_bbnone)
  elif isinstance(value, tuple):
    i = len(output)
    if not value:
      output.append(0)
    for item in value:
      output.append(_bbcommasp)
      append_portable_repr(output, item)
    output[i] = _bbop
    if len(value) == 1:
      output.append(_bbcommasp[:1])
    output.append(_bbcp)
  elif isinstance(value, list):
    i = len(output)
    if not value:
      output.append(0)
    for item in value:
      output.append(_bbcommasp)
      append_portable_repr(output, item)
    output[i] = _bbos
    output.append(_bbcs)
  elif isinstance(value, dict):
    i = len(output)
    if not value:
      output.append(0)
    # In Python 3, sorted fails if keys are of a different type.
    for key in sorted(value):
      output.append(_bbcommasp)
      if isinstance(key, str):
        key2 = bb(repr(bb(key)))  # This raises ValueError if not ASCII.
        if _bbbs in key2 or not key2.endswith(_bbsq):
          raise ValueError('Bad string key: %r' % key)
        output.append(key2.lstrip(_bbb))
      elif isinstance(key, bytes):  # This can fail in Python 3.x only.
        raise ValueError('Key must not be bytes.')
      else:
        append_portable_repr(output, key)
      output.append(_bbcolonsp)
      append_portable_repr(output, value[key])
    output[i] = _bbob
    output.append(_bbcb)
  else:
    raise TypeError('Unknown type for portable repr: %r' % type(value))


def portable_repr(value, suffix=bbe, _bbe=bbe):
  """Serializes data as bytes in Python 2.7, Python 3.x literal syntax. It's
  deterministic (e.g. dict iteration order). It emits ints as even-length
  hex. It doesn't distinguishes int vs long."""
  output = []
  append_portable_repr(output, value)
  output.append(suffix)
  return _bbe.join(output)


# --- RSA calculations.


def modinv(a, b, _divmod=divmod):
  """Returns the modular inverse of a, modulo b. b must be positive.

  If gcd(a, b) != 1, then no modular inverse exists, and ValueError is raised.

  Invariant: a * modinv(a, b) % b == 0.
  """
  # Implementation inspired by http://rosettacode.org/wiki/Modular_inverse#C
  # TODO(pts): Is the alternative implementation in pyecm for odd b faster?
  a0, b0 = a, b
  if b <= 0:
    raise ValueError('Modulus must be positive, got args: ' + repr((a0, b0)))
  a %= b
  if a < 0:
    a += b
  x0, x1 = 0, 1
  if a == 0:
    if b == 1:
      return 0
    raise ValueError('No modular inverse of 0: ' + repr((a0, b0)))
  while a > 1:
    if not b:
      raise ValueError('No modular inverse, not coprime: ' + repr((a0, b0)))
    r, q = _divmod(a, b)
    x0, x1, a, b = x1 - r * x0, x0, b, q
  return x1 + (x1 < 0 and b0)


def crt2(a1, m1, a2, m2):
  """Compute and return x using the Chinese remainder theorem.

  m1 amd m2 are the moduluses, and they must be coprimes.

  Returns:
    An integer a which is: 0 <= a < m1 * m2 and a % m1 == a1 and a % m2 == a2.
  Raises:
    ValueError: Iff no such unique a exists, i.e. iff gcd(m1, m2) != 1.
  """
  a1 %= m1  # Also makes it positive.
  a2 %= m2  # Also makes it positive.
  # http://en.wikipedia.org/wiki/Chinese_remainder_theorem#Case_of_two_equations_.28k_.3D_2.29
  return (m2 * modinv(m2, m1) * a1 + m1 * modinv(m1, m2) * a2) % (m1 * m2)


def gcd(a, b):
  """Returns the greatest common divisor of integers a and b.

  If both a and b are 0, then it returns 0.

  Similar to fractions.gcd, but works for negatives as well.
  """
  if a < 0:
    a = -a
  if b < 0:
    b = -b
  while b:
    a, b = b, a % b
  return a


def recover_rsa_prime1_from_exponents(modulus, private_exponent, public_exponent):
  """Efficiently recover non-trivial factors of n.

  From https://gist.github.com/flavienbwk/54671449419e1576c2708c9a3a711d78

  Typically Takes less than 10 seconds.

  See: Handbook of Applied Cryptography
  8.2.2 Security of RSA -> (i) Relation to factoring (p.287)
  http://www.cacr.math.uwaterloo.ca/hac/
  """
  import random
  t = (public_exponent * private_exponent - 1)
  s = 0
  while 1:
    quotient, remainder = divmod(t, 2)
    if remainder != 0:
      break
    s += 1
    t = quotient
  is_found = False
  modulus1 = modulus - 1
  while not is_found:
    i = 1
    a = random.randint(1, modulus1)
    while i <= s and not is_found:
      c1 = pow(a, pow(2, i - 1, modulus) * t, modulus)
      c2 = pow(a, pow(2, i, modulus) * t, modulus)
      is_found = c1 != 1 and c1 != modulus1 and c2 == 1
      i += 1
  p = gcd(c1 - 1, modulus)
  q = modulus // p
  return max(p, q)


def get_rsa_private_key(**kwargs):
  kwargs2 = {}
  for key in ('modulus', 'n', 'public_exponent', 'e', 'private_exponent', 'd', 'prime2', 'p', 'prime1', 'q', 'coefficient', 'u'):
    value = kwargs.get(key)
    if isinstance(value, (bytes, str)):
      kwargs2[key] = int(value, 16)
    elif isinstance(value, integer_types):
      kwargs2[key] = int(value)
    elif value is not None:
      raise TypeError('Bad value for key: %r' % (key,))
  modulus = kwargs2.get('modulus') or kwargs2.get('n') or 0
  public_exponent = kwargs2.get('public_exponent') or kwargs2.get('e') or 0  # Typically: 0x10001
  private_exponent = kwargs2.get('private_exponent') or kwargs2.get('d') or 0
  prime2 = kwargs2.get('prime2', kwargs2.get('p')) or 0
  prime1 = kwargs2.get('prime1', kwargs2.get('q')) or 0
  coefficient = kwargs2.get('coefficient') or kwargs2.get('u') or 0
  mc = bool(prime1) + bool(prime2) + bool(modulus)
  ec = bool(private_exponent) + bool(public_exponent)
  if mc < 2:
    if bool(prime1) and bool(coefficient):
      if not 0 < coefficient < prime1:
        raise ValueError('Bad coefficient.')
      prime2 = modinv(coefficient, prime1)
    elif bool(modulus) and ec == 2:
      if private_exponent <= 0:
        raise ValueError('Bad private_exponent.')
      if public_exponent <= 0:
        raise ValueError('Bad public_exponent.')
      if modulus <  2 * 3:
        raise ValueError('Bad modulus.')
      if private_exponent >= modulus:
        raise ValueError('Mismatch in private_exponent vs exponents.')
      if public_exponent >= modulus:
        raise ValueError('Mismatch in public_exponent vs exponents.')
      # Takes a few (10 seconds).
      prime1, prime2 = recover_rsa_prime1_from_exponents(modulus, private_exponent, public_exponent), 0
    else:
      # FYI It's also possible to recover the primes from other fields.
      # From (public_exponent, modulus, exponent1):
      #   # https://www.kangacrypt.info/files/NH.pdf
      #   With high probability, for some random a, prime1 == gcd(pow(a, public_exponent * exponent1 - 1, modulus) - 1, modulus) == prime1.
      # From (public_exponent, exponent1, exponent2):
      #   # https://eprint.iacr.org/2004/147.pdf
      #   It also works by brute-forcing public_exponent: 3 <= ... <= 0x10001.
      # From (public_exponent, modulus, coefficient):
      #   No answer yet on https://crypto.stackexchange.com/q/80254/
      raise ValueError('Needed (at least 2 of modulus, prime1, prime2) or (prime1, coefficient) or (modulus, public_exponent, private_exponent).')
  if not modulus:
    modulus = prime1 * prime2
  elif not prime1:
    prime1 = modulus // prime2
    if prime1 < 2:
      raise ValueError('modulus too small.')
  elif not prime2:
    prime2 = modulus // prime1
    if prime2 < 2:
      raise ValueError('modulus too small.')
  mc = bool(prime1) + bool(prime2) + bool(modulus)
  if mc < 3:
    raise ValueError('Found %d in modulus, prime1, prime2.' % mc)
  if prime1 <= prime2:
    if prime1 == prime2:
      raise ValueError('Primes must not be equal.')
    prime1, prime2 = prime2, prime1
  # True but slow: assert prime1 > prime2
  if prime1 < 3 or prime2 < 2:
    raise ValueError('Primes are too small.')
  if modulus != prime1 * prime2:
    raise ValueError('Mismatch in modulus vs primes.')
  if not (coefficient and prime2 * coefficient % prime1 == 1):
    try:
      coefficient = modinv(prime2, prime1)
    except ValueError:
      coefficient = None
    if coefficient is None:
      raise ValueError('Primes are not coprimes.')
  pp1 = (prime1 - 1) * (prime2 - 1)
  lcm = pp1 // gcd(prime1 - 1, prime2 - 1)
  if ec < 1:
    raise ValueError('Needed at least 1 of private_exponent, public_exponent.')
  if not 0 <= private_exponent < pp1:
    raise ValueError('Bad private_exponent.')
  if not 0 <= public_exponent < pp1:
    raise ValueError('Bad public_exponent.')
  if not private_exponent:
    # lcm instead of pp1 would also work, but produce different value.
    private_exponent = modinv(public_exponent, pp1)
  elif not public_exponent:
    # lcm instead of pp1 would also work, but produce different value.
    public_exponent = modinv(private_exponent, pp1)
  if private_exponent * public_exponent % lcm != 1:
    # Please note that it's OK that private_exponent * public_exponent % pp1 != 1.
    # Some GPG RSA keys are like this.
    raise ValueError('Mismatch in private_exponent vs public_exponent.')
  # These checks follow from `private_exponent * public_exponent % lcm == 1'.
  #if gcd(public_exponent, lcm) != 1:
  #  raise ValueError('Mismatch in public_exponent vs primes.')
  #if gcd(private_exponent, lcm) != 1:
  #  raise ValueError('Mismatch in private_exponent vs primes.')
  #
  # OpenPGP RSA private key:
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.6
  # * modulus: (public) MPI of RSA public modulus n;
  # * public_exponent: (public) MPI of RSA public encryption exponent e, usually 0x10001.
  # * private_exponent: MPI of RSA secret exponent d;
  # * prime2: (smaller prime) MPI of RSA secret prime value p;
  # * prime1: (larger prime) MPI of RSA secret prime value q (p < q);
  # * coefficient: MPI of u, the multiplicative inverse of p, mod q.
  d = {
      'modulus': modulus,  # Public.
      'prime1': prime1,
      'prime2': prime2,
      'public_exponent': public_exponent,  # Public.
      'private_exponent': private_exponent,
      'exponent1': private_exponent % (prime1 - 1),
      'exponent2': private_exponent % (prime2 - 1),
      'coefficient': coefficient,
  }
  for key in ('checkint', 'creation_time'):  # uint32.
    if key in kwargs and (not isinstance(kwargs[key], integer_types) or 0 > kwargs[key] or kwargs[key] >> 32):
      raise ValueError('Bad %s: %r' % (key, kwargs[key]))
  for key in ('comment', 'checkint', 'creation_time'):
    if key in kwargs:
      d.setdefault(key, kwargs[key])
  return d


def is_rsa_private_key_complete(d, effort=None):
  if effort is None:
    effort = 999  # Many checks.
  if not isinstance(d, dict):
    raise TypeError
  if not (
      d.get('modulus') and d.get('public_exponent') and
      d.get('private_exponent') and d.get('prime1') and d.get('prime2') and
      d.get('exponent1') and d.get('exponent2') and d.get('coefficient')):
    return False
  if effort >= 1:
    if not (
        isinstance(d['prime1'], integer_types) and
        isinstance(d['prime2'], integer_types) and
        isinstance(d['modulus'], integer_types) and
        2 < d['prime2'] < d['prime1'] < d['modulus']):
      return False
    pm1, pm2 = d['prime1'] - 1, d['prime2'] - 1
    pp1 = pm1 * pm2
    if not (
        isinstance(d['public_exponent'], integer_types) and
        isinstance(d['private_exponent'], integer_types) and
        1 <= d['private_exponent'] < pp1 and
        1 <= d['public_exponent'] < pp1):
      return False
    if effort >= 2 and d['modulus'] != d['prime1'] * d['prime2']:
      return False
    if effort >= 3:
      try:
        coefficient = modinv(d['prime2'], d['prime1'])
      except ValueError:
        coefficient = None
      if not (
          d['coefficient'] == coefficient and
          d['exponent1'] == d['private_exponent'] % pm1,
          d['exponent2'] == d['private_exponent'] % pm2):
        return False
      if effort >= 4:
        lcm = pp1 // gcd(pm1, pm2)
        if d['private_exponent'] * d['public_exponent'] % lcm != 1:
          return False
        # With `if effort >= 5' we could check that prime1 and prime2 are
        # primes.
  return True


# --- Random byte and uint generation.


def _get_random_bytes_urandom(size):
  import os
  return os.urandom(size)


def _get_random_bytes_winrandom(size):
  from ctypes import wintypes
  import ctypes
  PROV_RSA_FULL = 1
  s = cryptes.create_string_buffer(size)
  ok = ctypes.c_int()
  hProv = ctypes.c_ulong()
  ok = ctypes.windll.Advapi32.CryptAcquireContextA(ctypes.byref(hProv), None, None, PROV_RSA_FULL, 0)
  ok = ctypes.windll.Advapi32.CryptGenRandom(hProv, wintypes.DWORD(size), ctypes.cast(ctypes.byref(s), ctypes.POINTER(ctypes.c_byte)))
  if not ok:
    raise RuntimeError('Random generation failed.')
  return s.raw


def _get_random_bytes_python(size, _bbe=bbe, _pack=struct.pack):
  import random
  return _bbe.join(_pack('>B', random.randrange(0, 255)) for _ in xrange(size))


def get_random_bytes(size, _cache=[]):
  if not _cache:
    try:
      import os
      if not isinstance(os.urandom(1), bytes):
        raise ValueError
      _cache.append(_get_random_bytes_urandom)
    except (ImportError, AttributeError, ValueError, OSError, IOError, RuntimeError):
      try:
        from ctypes import wintypes
        import ctypes
        ctypes.windll.Advapi32.CryptAcquireContextA
        _cache.append(_get_random_bytes_winrandom)
      except (ImportError, AttributeError, ValueError, OSError, IOError, RuntimeError):
        _cache.append(_get_random_bytes_python)
  return _cache[0](size)


def get_random_uint_in_range(start, limit):
  """Returns random integer in the range: start <= result < limit."""
  d = limit - start
  if d <= 1:
    if d <= 0:
      raise ValueError('Empty range.')
    return start
  while 1:
    bitsize = get_uint_bitsize(d - 1)
    value = uint_from_be(get_random_bytes((bitsize + 7) >> 3))
    if bitsize & 7:
      value &= (1 << bitsize) - 1
    if value < d:
      return value + start


# --- RSA private key generation.


# Based on OpenSSL 1.1.0l BN_prime_checks_for_size.
# https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Testing_against_small_sets_of_bases
def get_miller_rabin_round_count_for_bitsize(bitsize):
  if bitsize >= 3747:
    return 3
  elif bitsize >= 1345:
    return 4
  elif bitsize >= 476:
    return 5
  elif bitsize >= 400:
    return 6
  elif bitsize >= 347:
    return 7
  elif bitsize >= 308:
    return 8
  elif bitsize >= 55:
    return 27


BASE_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)

ACCURATE_MILLER_RABIN_LIMIT = 3317044064679887385961981


def get_accurate_miller_rabin_bases(n):
  # https://oeis.org/A006945/list
  # https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Testing_against_small_sets_of_bases
  if n < 2152302898747:
    if n < 2047:
      c = 1
    elif n < 1373653:
      c = 2
    elif n < 25326001:
      c = 3
    elif n < 3215031751:
      c = 4
    elif n < 4759123141:
      return (2, 7, 61)
    else:  # elif n < 2152302898747:
      c = 5
  else:
    if n < 3474749660383:
      c = 6
    elif c < 341550071728321:
      c = 7
    elif n < 3825123056546413051:
      c = 9
    elif n < 318665857834031151167461:
      c = 12
    elif n < 3317044064679887385961981:
      c = 13
    else:
      raise ValueError('n is too large for accurate Miller-Rabin bases.')
  return BASE_PRIMES[:c]


def get_yield_miller_rabin_bases(n, bitsize=None):
  if n < ACCURATE_MILLER_RABIN_LIMIT:
    if n < 3:
      raise ValueError('n is too small for Miller-Rabin.')
    return iter(get_accurate_miller_rabin_bases(n))
  else:
    if bitsize is None:
      bitsize = get_uint_bitsize(n)
    round_count = get_miller_rabin_round_count_for_bitsize(bitsize)
    n3 = n - 3
    def yield_bases():
      c = round_count
      while c > 0:
        c -= 1
        yield 2 + get_random_uint_in_range(0, n3)
    return yield_bases()


def is_prime_miller_rabin(n, bitsize=None):
  if n <= BASE_PRIMES[-1]:
    # TODO(pts): Is bisect faster?
    return n > 1 and n in BASE_PRIMES
  if not (n & 1):
    return n == 2
  n1, k0 = n - 1, 1
  while not (n1 & (1 << k0)):
    k0 += 1
  n2 = n1 >> k0
  for a in get_yield_miller_rabin_bases(n, bitsize):
    # This pow(a, n2, n) call is the slowest step in generate_rsa (for
    # bitsize=2048 it's 64.85%, for bitsize=4096 it's 88.19%, for
    # bitsize=8192 it's 96.51%; here bitsize= is the argument of
    # generate_rsa).
    #
    # TODO(pts): Do Montgomery setup for mod n calculations, and use it here.
    # BN_mod_exp_mont(...) in openssl-1.1.0l/crypto/bn/bn_exp.c
    p = pow(a, n2, n)
    if p != 1 and p != n1:
      k = k0
      while k > 0:
        p = (p * p) % n
        if p == 1:
          return False  # Composite.
        if p == n1:
          break  # May be prime. Won't `return False' below.
        k -= 1
      if not k:
        return False  # Composite (non-prime).
  return True  # Probably prime.


SIEVE_PRIMES = (  # 2048 primes if 2 and 3 ares prepended.
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
    1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
    1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181,
    1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
    1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361,
    1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
    1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531,
    1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
    1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699,
    1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
    1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,
    1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
    1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083,
    2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
    2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273,
    2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
    2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441,
    2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
    2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663,
    2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
    2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,
    2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
    2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023,
    3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
    3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251,
    3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
    3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449,
    3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
    3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617,
    3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
    3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821,
    3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
    3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013,
    4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
    4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219,
    4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
    4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423,
    4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
    4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639,
    4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
    4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
    4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
    4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023,
    5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147,
    5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261,
    5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
    5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471,
    5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563,
    5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659,
    5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779,
    5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
    5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981,
    5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089,
    6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199,
    6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287,
    6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
    6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491,
    6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607,
    6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709,
    6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827,
    6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
    6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013,
    7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129,
    7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243,
    7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369,
    7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
    7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577,
    7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681,
    7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789,
    7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901,
    7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017,
    8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123,
    8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237,
    8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353,
    8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461,
    8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597,
    8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689,
    8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779,
    8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867,
    8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001,
    9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109,
    9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209,
    9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323,
    9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421,
    9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511,
    9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631,
    9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743,
    9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839,
    9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941,
    9949, 9967, 9973, 10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079,
    10091, 10093, 10099, 10103, 10111, 10133, 10139, 10141, 10151, 10159, 10163,
    10169, 10177, 10181, 10193, 10211, 10223, 10243, 10247, 10253, 10259, 10267,
    10271, 10273, 10289, 10301, 10303, 10313, 10321, 10331, 10333, 10337, 10343,
    10357, 10369, 10391, 10399, 10427, 10429, 10433, 10453, 10457, 10459, 10463,
    10477, 10487, 10499, 10501, 10513, 10529, 10531, 10559, 10567, 10589, 10597,
    10601, 10607, 10613, 10627, 10631, 10639, 10651, 10657, 10663, 10667, 10687,
    10691, 10709, 10711, 10723, 10729, 10733, 10739, 10753, 10771, 10781, 10789,
    10799, 10831, 10837, 10847, 10853, 10859, 10861, 10867, 10883, 10889, 10891,
    10903, 10909, 10937, 10939, 10949, 10957, 10973, 10979, 10987, 10993, 11003,
    11027, 11047, 11057, 11059, 11069, 11071, 11083, 11087, 11093, 11113, 11117,
    11119, 11131, 11149, 11159, 11161, 11171, 11173, 11177, 11197, 11213, 11239,
    11243, 11251, 11257, 11261, 11273, 11279, 11287, 11299, 11311, 11317, 11321,
    11329, 11351, 11353, 11369, 11383, 11393, 11399, 11411, 11423, 11437, 11443,
    11447, 11467, 11471, 11483, 11489, 11491, 11497, 11503, 11519, 11527, 11549,
    11551, 11579, 11587, 11593, 11597, 11617, 11621, 11633, 11657, 11677, 11681,
    11689, 11699, 11701, 11717, 11719, 11731, 11743, 11777, 11779, 11783, 11789,
    11801, 11807, 11813, 11821, 11827, 11831, 11833, 11839, 11863, 11867, 11887,
    11897, 11903, 11909, 11923, 11927, 11933, 11939, 11941, 11953, 11959, 11969,
    11971, 11981, 11987, 12007, 12011, 12037, 12041, 12043, 12049, 12071, 12073,
    12097, 12101, 12107, 12109, 12113, 12119, 12143, 12149, 12157, 12161, 12163,
    12197, 12203, 12211, 12227, 12239, 12241, 12251, 12253, 12263, 12269, 12277,
    12281, 12289, 12301, 12323, 12329, 12343, 12347, 12373, 12377, 12379, 12391,
    12401, 12409, 12413, 12421, 12433, 12437, 12451, 12457, 12473, 12479, 12487,
    12491, 12497, 12503, 12511, 12517, 12527, 12539, 12541, 12547, 12553, 12569,
    12577, 12583, 12589, 12601, 12611, 12613, 12619, 12637, 12641, 12647, 12653,
    12659, 12671, 12689, 12697, 12703, 12713, 12721, 12739, 12743, 12757, 12763,
    12781, 12791, 12799, 12809, 12821, 12823, 12829, 12841, 12853, 12889, 12893,
    12899, 12907, 12911, 12917, 12919, 12923, 12941, 12953, 12959, 12967, 12973,
    12979, 12983, 13001, 13003, 13007, 13009, 13033, 13037, 13043, 13049, 13063,
    13093, 13099, 13103, 13109, 13121, 13127, 13147, 13151, 13159, 13163, 13171,
    13177, 13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259, 13267, 13291,
    13297, 13309, 13313, 13327, 13331, 13337, 13339, 13367, 13381, 13397, 13399,
    13411, 13417, 13421, 13441, 13451, 13457, 13463, 13469, 13477, 13487, 13499,
    13513, 13523, 13537, 13553, 13567, 13577, 13591, 13597, 13613, 13619, 13627,
    13633, 13649, 13669, 13679, 13681, 13687, 13691, 13693, 13697, 13709, 13711,
    13721, 13723, 13729, 13751, 13757, 13759, 13763, 13781, 13789, 13799, 13807,
    13829, 13831, 13841, 13859, 13873, 13877, 13879, 13883, 13901, 13903, 13907,
    13913, 13921, 13931, 13933, 13963, 13967, 13997, 13999, 14009, 14011, 14029,
    14033, 14051, 14057, 14071, 14081, 14083, 14087, 14107, 14143, 14149, 14153,
    14159, 14173, 14177, 14197, 14207, 14221, 14243, 14249, 14251, 14281, 14293,
    14303, 14321, 14323, 14327, 14341, 14347, 14369, 14387, 14389, 14401, 14407,
    14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461, 14479, 14489, 14503,
    14519, 14533, 14537, 14543, 14549, 14551, 14557, 14561, 14563, 14591, 14593,
    14621, 14627, 14629, 14633, 14639, 14653, 14657, 14669, 14683, 14699, 14713,
    14717, 14723, 14731, 14737, 14741, 14747, 14753, 14759, 14767, 14771, 14779,
    14783, 14797, 14813, 14821, 14827, 14831, 14843, 14851, 14867, 14869, 14879,
    14887, 14891, 14897, 14923, 14929, 14939, 14947, 14951, 14957, 14969, 14983,
    15013, 15017, 15031, 15053, 15061, 15073, 15077, 15083, 15091, 15101, 15107,
    15121, 15131, 15137, 15139, 15149, 15161, 15173, 15187, 15193, 15199, 15217,
    15227, 15233, 15241, 15259, 15263, 15269, 15271, 15277, 15287, 15289, 15299,
    15307, 15313, 15319, 15329, 15331, 15349, 15359, 15361, 15373, 15377, 15383,
    15391, 15401, 15413, 15427, 15439, 15443, 15451, 15461, 15467, 15473, 15493,
    15497, 15511, 15527, 15541, 15551, 15559, 15569, 15581, 15583, 15601, 15607,
    15619, 15629, 15641, 15643, 15647, 15649, 15661, 15667, 15671, 15679, 15683,
    15727, 15731, 15733, 15737, 15739, 15749, 15761, 15767, 15773, 15787, 15791,
    15797, 15803, 15809, 15817, 15823, 15859, 15877, 15881, 15887, 15889, 15901,
    15907, 15913, 15919, 15923, 15937, 15959, 15971, 15973, 15991, 16001, 16007,
    16033, 16057, 16061, 16063, 16067, 16069, 16073, 16087, 16091, 16097, 16103,
    16111, 16127, 16139, 16141, 16183, 16187, 16189, 16193, 16217, 16223, 16229,
    16231, 16249, 16253, 16267, 16273, 16301, 16319, 16333, 16339, 16349, 16361,
    16363, 16369, 16381, 16411, 16417, 16421, 16427, 16433, 16447, 16451, 16453,
    16477, 16481, 16487, 16493, 16519, 16529, 16547, 16553, 16561, 16567, 16573,
    16603, 16607, 16619, 16631, 16633, 16649, 16651, 16657, 16661, 16673, 16691,
    16693, 16699, 16703, 16729, 16741, 16747, 16759, 16763, 16787, 16811, 16823,
    16829, 16831, 16843, 16871, 16879, 16883, 16889, 16901, 16903, 16921, 16927,
    16931, 16937, 16943, 16963, 16979, 16981, 16987, 16993, 17011, 17021, 17027,
    17029, 17033, 17041, 17047, 17053, 17077, 17093, 17099, 17107, 17117, 17123,
    17137, 17159, 17167, 17183, 17189, 17191, 17203, 17207, 17209, 17231, 17239,
    17257, 17291, 17293, 17299, 17317, 17321, 17327, 17333, 17341, 17351, 17359,
    17377, 17383, 17387, 17389, 17393, 17401, 17417, 17419, 17431, 17443, 17449,
    17467, 17471, 17477, 17483, 17489, 17491, 17497, 17509, 17519, 17539, 17551,
    17569, 17573, 17579, 17581, 17597, 17599, 17609, 17623, 17627, 17657, 17659,
    17669, 17681, 17683, 17707, 17713, 17729, 17737, 17747, 17749, 17761, 17783,
    17789, 17791, 17807, 17827, 17837, 17839, 17851, 17863,
)

SIEVE_LIMIT = SIEVE_PRIMES[-1] ** 2
SIEVE_BITSIZE11 = get_uint_bitsize(SIEVE_PRIMES[-1] ** 2 - 1) - 1  # 28.
SIEVE_BITSIZE1 = get_uint_bitsize(SIEVE_PRIMES[-1]) - 1  # 14.


def is_small_prime(n, _sp=SIEVE_PRIMES):
  if n >= SIEVE_LIMIT:
    return False
  if n < 4:
    return n > 1
  if not (n & 1):
    return False
  if not (n % 3):
    return False
  b = a = 1 << ((get_uint_bitsize(n) - 1) >> 1)  # First approximation.
  a = (a + n // a) >> 1; c = a; a = (a + n // a) >> 1
  while a != b:  # Newton iteration for floor of square root.
    b = a; a = (a + n // a) >> 1; c = a; a = (a + n // a) >> 1
  if a < c:
    sqrtlimit = a + 1
  else:
    sqrtlimit = c + 1
  for p in _sp:
    if p >= sqrtlimit:
      return True
    if not (n % p):
      return False
  return True


def get_random_prime(bitsize, is_low=False, limit=None, _sp=SIEVE_PRIMES):
  """Generates a random prime good for RSA, of size bitsize, smaller than limit.

  Args:
    bitsize: Number of bits of the result. The first bit will be 1.
    is_low: If true, then the minimum result is 1 << (bitsize - 1), otherwise
        it is 3 << (bitsize - 2). The latter use useful for ensuring that the
        product of two random prime numbers returned by this function will have
        its top bit as 1 (3 / 4 * 3 / 4 == 9 / 16 >= 1 /2).
    limit: If not None, then the result must be smaller than limit. The default
        limit is 1 << bitsize.
  Returns:
    A prime number of size bitsize, smaller than limit.
  """
  if bitsize < 3:
    raise ValueError('bitsize too small: %d' % bitsize)
  b23 = 3 - bool(is_low)
  # Set top 2 bits (p * q to be large enough in RSA). Also make it odd.
  start1 = b23 << (bitsize - 3)
  bitsizep = 1 << (bitsize - 1)
  if limit is None:
    limit1 = bitsizep
    if b23 == 2:
      limit1 -= 1 << (bitsize - 3)
  else:
    limit1 = limit >> 1
    if limit1 <= start1:
      raise ValueError('Prime limit is too small: start=%d limit=%d' % (start1 << 1 | 1, limit))
    elif limit1 > (1 << bitsize):
      raise ValueError('Prime limit is too large: %d' % limit)
  del bitsizep  # Save memory.
  limit = limit1 << 1
  if bitsize <= SIEVE_BITSIZE11:
    # * Possible return values for is_low=False, limit=None:
    #   bitsize=3: 7
    #   bitsize=4: 13
    #   bitsize=5: 29 31
    #   bitsize=6: 53 59 61
    #   bitsize=7: 97 101 103 107 109 113 127
    #   bitsize=8: 193 197 199 211 223 227 229 233 239 241 251
    # * Possible return values for is_low=True, limit=None:
    #   bitsize=3: 5
    #   bitsize=4: 11
    #   bitsize=5: 17 19 23
    #   bitsize=6: 37 41 43 47
    #   bitsize=7: 67 71 73 79 83 89
    #   bitsize=8: 131 137 139 149 151 157 163 167 173 179 181 191
    n = limit - 1
    b = a = 1 << ((bitsize - 1) >> 1)  # First approximation.
    a = (a + n // a) >> 1; c = a; a = (a + n // a) >> 1
    while a != b:  # Newton iteration for floor of square root.
      b = a; a = (a + n // a) >> 1; c = a; a = (a + n // a) >> 1
    if a < c:
      sqrtlimit = a + 1
    else:
      sqrtlimit = c + 1
    # assert sqrtlimit <= (1 << (bitsize - 1)) <= n  # True but slow.
    # Faster than `sp = [p for p in _sp if p < sqrtlimit]', using inlined
    # bisect.bisect_left.
    lo, hi = 0, len(_sp)
    while lo < hi:
      mid = (lo + hi) >> 1
      if _sp[mid] < sqrtlimit:
        lo = mid + 1
      else:
        hi = mid
    sp = _sp[:lo]
    mlimit = int(bitsize > SIEVE_BITSIZE1)
    while 1:
      # This will fail with ValueError if the original input range is
      # exhausted.
      limit1 = get_random_uint_in_range(start1, limit1)
      n = limit1 << 1 | 1
      m = n % 3
      if m <= mlimit:
        n += 2 + (m << 1)  # So that n % 6 becomes 5.
      while n < limit:
        for p in sp:
          if n % p <= mlimit:  # Found a divisor of n or n - 1.
            break
        else:
          # n is prime, because it doesn't have any prime divisors
          # (up to sqrtlimit, which is large enough if bitsize <=
          # SIEVE_BITSIZE11.
          return n
        if mlimit:
          n += 6
        elif n % 6 == 1:
          n += 4
        else:
          n += 2
  while 1:
    # This will fail with ValueError if the original input range is
    # exhausted.
    r = get_random_uint_in_range(start1, limit1)
    n = r << 1 | 1
    m = n % 3
    if m <= 1:
      n += 2 + (m << 1)  # So that n % 6 becomes 5.
    while n < limit:
      for p in _sp:
        if n % p <= 1:  # n or n - 1 has a small prime divisor, so n isn't good.
          break
      else:  # No small prime divisors of n or n - 1.
        # This call is the slowest because of large pow(...).
        if is_prime_miller_rabin(n, bitsize):
          return n
        n += 6
        break  # Generate new random n.  Seems to make it faster.
      # BN_generate_prime_ex(...) in OpenSSL 1.1.0l uses the `mods' array to
      # make this `+=' faster by calling it less often. In Python it just
      # makes it slower, and pow(a, n2, n) is much slower anyway.
      n += 6
    if n >= limit:
      limit1 = r  # Decrease the limit for subsequent random numbers.
    if r == start1:  # Very unlikely, but helps testing.
      start1 = n >> 1


def generate_rsa(bitsize, e=None, is_close_odd=False):
  """Generates a random RSA private key and returns it in dict (d) format.

  Args:
    bitsize: Number of bits in result['modulus']. Must be at least 4.
        Recommended secure value in 2020: 4096.
    e: Force value of result['public_exponent']. If unspecified, the default
        0x10001 will be used if bitsize >= 17, otherwise 0x101, 0x11 or 5
        will be used, depending on bitsize.
    is_close_odd: If true and bitsize is odd and bitsize is at least 11, then
        both result['prime1'] and result['prime2'] will have bitsize >> 1 bits.
        If false, then (just like by OpenSSL 1.1.0l),
        result['prime1'] will have bitsize >> 1 | 1 bits, and
        result['prime2'] will have bitsize >> 1 bits.
  Returns:
    An RSA private key dict (same as of get_rsa_private_key).
  """
  if bitsize < 4:
    raise ValueError('bitsize too small: %d' % bitsize)
  if e is None:
    if bitsize >= 17:
      e, ep = 0x10001, True
    elif bitsize >= 11:
      e, ep = 0x101, True
  else:
    if e >= (3 << (bitsize - 2)):  # Rule of thumb to avoid no relative primes.
      raise ValueError('e is too large.')
    if e < 3:
      raise ValueError('e is too small.')
    if not (e & 1):
      raise ValueError('e is even.')
    ep = is_small_prime(e)
  if bitsize < 11:
     # get_random_prime works with a few lower values as well. We hardcode
     # so that we have more than one return value (for GPG main key and GPG
     # subkey).
    if bitsize == 10:
      if get_random_uint_in_range(0, 2):
        p, q, e0 = 29, 31, 17
      else:
        p, q, e0 = 23, 31, 17
    elif bitsize == 9:
      if get_random_uint_in_range(0, 2):
        p, q, e0 = 19, 23, 17
      else:
        # p, q, e0 = 17, 23, 5
        p, q, e0 = 13, 31, 17
    elif bitsize == 8:
      if get_random_uint_in_range(0, 2):
        p, q, e0 = 11, 23, 17
      else:
        p, q, e0 = 13, 19, 17
    elif bitsize == 7:
      if get_random_uint_in_range(0, 2):
        p, q, e0 = 7, 13, 17
      else:
        p, q, e0 = 7, 11, 17
    elif bitsize == 6:
      if get_random_uint_in_range(0, 2):
        p, q, e0 = 5, 11, 17
      else:
        p, q, e0 = 5, 7, 17
    elif bitsize == 5:
      p, q, e0 = 3, 7, 5  # No other 16 <= p * q <= 31.
    elif bitsize == 4:
      p, q, e0 = 3, 5, 5  # No other 8 <= p * q <= 15.
    p1, q1 = p - 1, q - 1
    if e is None:
      e, ep = e0, True
    else:
      if ep:
        is_good = (p1 % e and q1 % e)
      else:
        is_good = gcd(p1, e) == 1 and gcd(q1, e) == 1
      if not is_good:
        raise ValueError('Generated small p and q do not match e. To fix, omit e.')
    n = p * q
  elif bitsize & 1 and is_close_odd:
    pq_bitsize = (bitsize >> 1) + 1
    while 1:
      p = get_random_prime(pq_bitsize, True)
      p1 = p - 1
      if ep:
        if not (p1 % e):  # Faster than gcd(p - 1, e).
          continue
      else:
        if gcd(p1, e) != 1:
          continue
      break
    q_limit = ((1 << bitsize) - 1) // p + 1
    while 1:
      q = get_random_prime(pq_bitsize, True, q_limit)
      if p == q:
        continue
      q1 = q - 1
      if ep:
        if not (q1 % e):  # Faster than gcd(q - 1, e).
          continue
      else:
        if gcd(q1, e) != 1:
          continue
      break
    n = p * q
    assert get_uint_bitsize(n) == bitsize, (p, q, n)
  else:
    p_bitsize = (bitsize + 1) >> 1  # OpenSSL 1.1.0l.
    q_bitsize = bitsize - p_bitsize
    while 1:
      p = get_random_prime(p_bitsize)
      p1 = p - 1
      if ep:
        if not (p1 % e):  # Faster than gcd(p - 1, e).
          continue
      else:
        if gcd(p1, e) != 1:
          continue
      break
    while 1:
      q = get_random_prime(q_bitsize)
      if p == q:
        continue
      q1 = q - 1
      if ep:
        if not (q1 % e):  # Faster than gcd(q - 1, e).
          continue
      else:
        if gcd(q1, e) != 1:
          continue
      break
    n = p * q
  if p > q:
    p, q, p1, q1 = q, p, q1, p1
  pq1 = p1 * q1
  dd = modinv(e, pq1)
  return {'modulus': n, 'public_exponent': e, 'prime1': q, 'prime2': p,
          'coefficient': modinv(p, q), 'private_exponent': dd,
          'exponent1': dd % q1, 'exponent2': dd % p1}


def is_bitsize_of_single_rsa_key(bitsize):
  """Returns bool indicating whether generate_rsa returns only a single RSA key."""
  return bitsize < 6


# --- Hashes.


try:
  new_sha1 = __import__('hashlib').sha1  # Python 2.5--.
except (ImportError, AttributeError):
  try:
    new_sha1 = __import__('_hashlib').openssl_sha1  # Some half-installed Python 3.1 packages have this.
  except (ImportError, AttributeError):
    try:
      new_sha1 = __import__('_sha1').sha1  # Some half-installed Python 3.1 packages have this.
    except (ImportError, AttributeError):
      try:
        new_sha1 = __import__('sha').sha  # Python 2.4.
      except (ImportError, AttributeError):
        new_sha1 = None
if not new_sha1:
  raise ImportError('SHA-1 hash implementation not found.')


try:
  new_sha256 = __import__('hashlib').sha256
except (ImportError, AttributeError):
  new_sha256 = None

if not new_sha256:
  def _sha256_rotr32(x, y):
    return ((x >> y) | (x << (32 - y))) & 0xffffffff


  _sha256_k = (
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)


  def slow_sha256_process(block, hh, _izip=izip, _rotr32=_sha256_rotr32, _k=_sha256_k):
    w = [0] * 64
    w[:16] = struct.unpack('>16L', block)
    for i in xrange(16, 64):
      w[i] = (w[i - 16] + (_rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 7] + (_rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10))) & 0xffffffff
    a, b, c, d, e, f, g, h = hh
    for i in xrange(64):
      t1 = h + (_rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)) + ((e & f) ^ ((~e) & g)) + _k[i] + w[i]
      t2 = (_rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))
      a, b, c, d, e, f, g, h = (t1 + t2) & 0xffffffff, a, b, c, (d + t1) & 0xffffffff, e, f, g
    return [(x + y) & 0xffffffff for x, y in _izip(hh, (a, b, c, d, e, f, g, h))]


  del _sha256_rotr32, _sha256_k  # Unpollute namespace.


  # Fallback pure Python implementation of SHA-256 based on
  # https://github.com/thomdixon/pysha2/blob/master/sha2/sha256.py
  # It is about 400+ times slower than OpenSSL's C implementation.
  #
  # This is used in Python 2.4 by default. (Python 2.5 already has
  # hashlib.sha256.)
  #
  # Most users shouldn't be using this, because it's too slow in production
  # (as used in pbkdf2). Python 2.4 users are encouraged to upgrade to
  # Python >=2.5, install hashlib or pycrypto from PyPi, all of which
  # contain a faster SHA-256 implementation in C.
  class Slow_sha256(object):
    _h0 = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    block_size = 64
    digest_size = 32

    __slots__ = ('_buffer', '_counter', '_h')

    def __init__(self, m=None, _bbe=bbe):
      self._buffer = bbe
      self._counter = 0
      self._h = self._h0
      if m is not None:
        self.update(m)

    def update(self, m):
      if not isinstance(m, bytes):
        raise TypeError('update() argument 1 must be string, not %s' % (type(m).__name__))
      if not m:
        return
      buf, process = self._buffer, slow_sha256_process
      lb, lm = len(buf), len(m)
      self._counter += lm
      self._buffer = None
      if lb + lm < 64:
        buf += bytes(m)
        self._buffer = buf
      else:
        hh, i = self._h, 0
        if lb:
          assert lb < 64
          i = 64 - lb
          hh = process(buf + bytes(m[:i]), hh)
        for i in xrange(i, lm - 63, 64):
          hh = process(m[i : i + 64], hh)
        self._h = hh
        self._buffer = bytes(m[lm - ((lm - i) & 63):])

    def digest(self):
      c = self._counter
      if (c & 63) < 56:
        return struct.pack('>8L', *slow_sha256_process(self._buffer + struct.pack('>B%dxQ' % (55 - (c & 63)), 0x80, c << 3), self._h))
      else:
        return struct.pack('>8L', *slow_sha256_process(struct.pack('>56xQ', c << 3), slow_sha256_process(self._buffer + struct.pack('>B%dx' % (~c & 63), 0x80), self._h)))

    def hexdigest(self):
      return to_hex_str(self.digest())

    def copy(self):
      other = type(self)()
      other._buffer, other._counter, other._h = self._buffer, self._counter, self._h
      return other

  new_sha256 = Slow_sha256


# -- GPG private key and private subkey serialization.


def emsa_pkcs1_v1_5(t, n):
  # https://tools.ietf.org/html/rfc3447#section-9.2
  n_size, t_size = get_uint_byte_size(n), get_uint_byte_size(t)
  if n_size < t_size + 11:
    raise ValueError('n is too short (to fix, increase <bitsize>): %d < %d' % (n_size, t_size + 11))
  # Same but slower: return -1 & ((1 << ((n_size << 3) - 15)) - (1 << ((t_size + 1) << 3))) | t
  return (1 << ((n_size << 3) - 15)) - ((1 << ((t_size + 1) << 3)) - t)


# (hash_name, hash_algo, hash_size, asn1_header).
# https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.2.2
# TODO(pts): Add md5 and sha*.
GPG_HASH_INFOS = {
    'sha1': ('sha1', 2, 20, binascii.unhexlify(bb('3021300906052b0e03021a05000414')), new_sha1),
    # 3031: sequence of 49 bytes
    #   300D: sequence of 13 bytes
    #     0609: oid of 9 bytes
    #       608648016503040201: OID of SHA-256
    #     0500: None
    #   0420: uint of 32 bytes
    #     ????????????????????????????????????????????????????????????????: sha256_hexdigest
    'sha256': ('sha256', 8, 32, binascii.unhexlify(bb('3031300d060960864801650304020105000420')), new_sha256),
}


def get_gpg_hash_info(hash_name):
  hash_name = hash_name.lower().replace('-', '')
  if hash_name not in GPG_HASH_INFOS:
    raise ValueError('Unknown hash: %r' % hash)
  return GPG_HASH_INFOS[hash_name]


def build_gpg_signature_digest(hash_name, public_key_packet_data, second_packet_data, hashed_subpackets_data, signature_type):
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.2.4
  # write_signature_packets(...) and hash_sigversion_to_magic(...) in gnupg-1.4.16/g10/sign.c
  hash_name, hash_algo, hash_size, asn1_header, hash_cons = get_gpg_hash_info(hash_name)
  h = hash_cons()
  h.update(struct.pack('>BH', 0x99, len(public_key_packet_data)))
  h.update(public_key_packet_data)
  if signature_type == 0x18:
    h.update(struct.pack('>BH', 0x99, len(second_packet_data)))
  elif 0x10 <= signature_type <= 0x13:
    h.update(struct.pack('>BL', 0xb4, len(second_packet_data)))
  else:
    raise ValueError('Bad signature type: 0x%x' % signature_type)
  h.update(second_packet_data)
  public_key_algo = 1  # RSA.
  h.update(struct.pack('>BBBBH', 4, signature_type, public_key_algo, hash_algo, len(hashed_subpackets_data)))
  h.update(hashed_subpackets_data)
  h.update(struct.pack('>HL', 0x04ff, 6 + len(hashed_subpackets_data)))
  hd = h.digest()
  return asn1_header + hd, hd[:2]


def append_gpg_mpi(output, value):
  """Returns a GPG MPI representation of uint value."""
  if not isinstance(value, integer_types):
    raise ValueError
  if value < 0:
    raise TypeError('Negative GPG MPI.')
  output.append(struct.pack('>H', get_uint_bitsize(value)))
  output.append(uint_to_any_be(value))


def build_gpg_rsa_public_key_packet_data(d, creation_time=None, _bbe=bbe, _bbz=bbz):
  """Returns the packet bytes without the tag and size header."""
  if not isinstance(d.get('creation_time'), integer_types):
    raise ValueError('Bad or missing GPG RSA public key creation time.')
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.5.2
  public_key_algo = 1  # RSA.
  if creation_time is None:
    creation_time = d['creation_time']
  output = [struct.pack('>BLB', 4, creation_time, public_key_algo)]
  append_gpg_mpi(output, d['modulus'])
  append_gpg_mpi(output, d['public_exponent'])
  return _bbe.join(output)


def build_gpg_rsa_private_key_packet_data(d, _bbe=bbe, _bbz=bbz):
  """Returns the packet bytes without the tag and size header."""
  if not isinstance(d.get('creation_time'), integer_types):
    raise ValueError('Bad or missing GPG RSA private key creation time.')
  public_key_algo = 1  # RSA.
  output = [struct.pack('>BLB', 4, d['creation_time'], public_key_algo)]
  append_gpg_mpi(output, d['modulus'])
  append_gpg_mpi(output, d['public_exponent'])
  output.append(bbz)  # Unprotected.
  i = len(output)
  append_gpg_mpi(output, d['private_exponent'])
  append_gpg_mpi(output, d['prime2'])
  append_gpg_mpi(output, d['prime1'])
  append_gpg_mpi(output, d['coefficient'])
  output.append(struct.pack('>H', sum(sum(struct.unpack('>%dB' % len(x), x)) for x in output[i:]) & 0xffff))
  return _bbe.join(output)


def rsa_encrypt(d, data):
  """Takes bytes or uint, returns a uint."""
  if isinstance(data, bytes):
    x = emsa_pkcs1_v1_5(uint_from_be(data), d['modulus'])
  elif isinstance(data, integer_types):
    x = data
  else:
    raise TypeError
  if 'coefficient' in d:  # Fastest to compute, because mp1 and mp2 modular exponentiation have small (half-size) modulus.
    mp1 = pow(x, d.get('exponent1') or d['private_exponent'] % (d['prime1'] - 1), d['prime1'])
    mp2 = pow(x, d.get('exponent2') or d['private_exponent'] % (d['prime2'] - 1), d['prime2'])
    # For additional speedup, we could also cache d['prime2'] * d['coefficient'] % d['modulus'].
    return (mp2 + d['prime2'] * d['coefficient'] * (mp1 - mp2)) % d['modulus']
  else:
    return pow(x, d['private_exponent'], d['modulus'])


def build_gpg_rsa_signature_packet_data(d, signature_type, public_subkey_packet_data, hash_name, public_key_packet_data, hashed_subpackets_data, unhashed_subpackets_data, _bbe=bbe):
  public_key_algo = 1  # RSA.
  digest, digest_prefix2 = build_gpg_signature_digest(hash_name, public_key_packet_data, public_subkey_packet_data, hashed_subpackets_data, signature_type)
  hash_algo = get_gpg_hash_info(hash_name)[1]
  output = [struct.pack('>BBBBH', 4, signature_type, public_key_algo, hash_algo, len(hashed_subpackets_data)), hashed_subpackets_data,
            struct.pack('>H', len(unhashed_subpackets_data)), unhashed_subpackets_data, digest_prefix2]
  append_gpg_mpi(output, rsa_encrypt(d, digest))  # RSA signature.
  return _bbe.join(output)


# https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.2.3.22
GPG_KEY_FLAG_CERTIFY = 1
GPG_KEY_FLAG_SIGN = 2
GPG_KEY_FLAG_ENCRYPT = 4 | 8
GPG_KEY_FLAG_AUTHENTICATE = 32


def build_gpg_key_id20(public_key_packet_data):
  h = new_sha1()
  h.update(struct.pack('>BH', 0x99, len(public_key_packet_data)))
  h.update(public_key_packet_data)
  key_id20 = h.digest()
  assert len(key_id20) == 20
  return key_id20


def build_gpg_subpacket_from_uint8s(subpacket_type, values):
  if len(values) > 191:
    raise ValueError('Too many int values in subpacket.')
  return struct.pack('>%dB' % (len(values) + 2), len(values) + 1, subpacket_type, *values)


def build_gpg_subkey_rsa_signature_packet_data(d, public_subkey_packet_data, hash_name, public_key_packet_data=None, key_id20=None, subkey_flags=GPG_KEY_FLAG_ENCRYPT, signature_creation_time=None, _bbv4=bb('\4')):
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.2.3
  if not isinstance(d.get('creation_time'), integer_types):
    raise ValueError('Bad or missing GPG RSA private key creation time.')
  if not isinstance(public_subkey_packet_data, bytes):
    raise TypeError
  if not (public_subkey_packet_data.startswith(_bbv4) and len(public_subkey_packet_data) >= 8):
    raise ValueError('Bad public subkey packet data.')
  if signature_creation_time is None:
    signature_creation_time, = struct.unpack('>L', public_subkey_packet_data[1 : 5])
  if public_key_packet_data is None:
    public_key_packet_data = build_gpg_rsa_public_key_packet_data(d)
  if key_id20 is None:
    key_id20 = build_gpg_key_id20(public_key_packet_data)
  hashed_subpackets_data = struct.pack('>HB20sHLHB', 0x1621, 4, key_id20, 0x0502, signature_creation_time, 0x021B, subkey_flags)
  unhashed_subpackets_data = struct.pack('>H8s', 0x0910, key_id20[-8:])
  signature_type = 0x18  # Subkey Binding Signature.
  return build_gpg_rsa_signature_packet_data(d, signature_type, public_subkey_packet_data, hash_name, public_key_packet_data, hashed_subpackets_data, unhashed_subpackets_data)


def build_gpg_userid_cert_rsa_signature_packet_data(d, hash_name, public_key_packet_data=None, key_id20=None,
                                                    key_flags=GPG_KEY_FLAG_CERTIFY | GPG_KEY_FLAG_SIGN,
                                                    signature_type=0x13,  # Positive certification of a User ID and Public-Key packet.
                                                    preferred_cipher_algos=(9, 8, 7, 2),  preferred_hash_algos=(8, 9, 10, 11, 2), preferred_compress_algos=(2, 3, 1),
                                                    signature_creation_time=None, _bbe=bbe):
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.2.3
  if not isinstance(d.get('creation_time'), integer_types):
    raise ValueError('Bad or missing GPG RSA private key creation time.')
  if not isinstance(d.get('comment'), bytes):
    raise ValueError('Bad or missing GPG RSA private key userid comment.')
  if not isinstance(signature_type, integer_types):
    raise TypeError
  if not 0x10 <= signature_type <= 0x13:
    raise ValueError('Bad GPG userid cert signature type: 0x%x' % signature_type)
  if signature_creation_time is None:
    signature_creation_time = d['creation_time']
  if public_key_packet_data is None:
    public_key_packet_data = build_gpg_rsa_public_key_packet_data(d)
  if key_id20 is None:
    key_id20 = build_gpg_key_id20(public_key_packet_data)
  features = (1,)
  keyserver_preferences = (0x80,)
  if isinstance(key_flags, integer_types):
    key_flags = (key_flags,)
  hashed_subpackets_data = _bbe.join((
      struct.pack('>HB20sHL', 0x1621, 4, key_id20, 0x0502, signature_creation_time),
      build_gpg_subpacket_from_uint8s(27, key_flags),
      build_gpg_subpacket_from_uint8s(11, preferred_cipher_algos),
      build_gpg_subpacket_from_uint8s(21, preferred_hash_algos),
      build_gpg_subpacket_from_uint8s(22, preferred_compress_algos),
      build_gpg_subpacket_from_uint8s(30, features),
      build_gpg_subpacket_from_uint8s(23, keyserver_preferences),
  ))
  unhashed_subpackets_data = struct.pack('>H8s', 0x0910, key_id20[-8:])
  return build_gpg_rsa_signature_packet_data(d, signature_type, d['comment'], hash_name, public_key_packet_data, hashed_subpackets_data, unhashed_subpackets_data)


def build_gpg_packet_header(packet_type, size, _pack=struct.pack):
  if not 1 <= packet_type <= 63:
    raise ValueError('Invalid GPG packet type: %d' % packet_type)
  if size < 0:
    raise ValueError('To-be-created GPG packet has negative size.')
  elif size < 256 and packet_type < 16:
    return _pack('>BB', 128 | (packet_type << 2), size)
  elif size < 192:
    return _pack('>BB', 192 | packet_type, size)
  elif size < 65536 and packet_type < 16:
    return _pack('>BH', 129 | (packet_type << 2), size)
  elif size < 8192 + 192:
    b = size - 192
    return _pack('>BBB', 192 | packet_type, 192 | b >> 8, b & 255)
  elif size >> 32:
    raise ValueError('To-be-created GPG packet too large.')
  elif packet_type < 16:
    return _pack('>BL', 130 | (packet_type << 2), size)
  else:
    return _pack('>BBL', 192 | packet_type, 255, size)


def skip_gpg_mpis(data, i, mpi_count):
  while mpi_count > 0:
    mpi_count -= 1
    # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-3.2
    if i + 2 > len(data):
      raise ValueError('GPG MPI too short.')
    bitsize, = struct.unpack('>H', data[i : i + 2])
    i += 2
    #if not bitsize:  # Let's be permissive.
    #  raise ValueError('Empty GPG MPI.')
    size = (bitsize + 7) >> 3
    if i + size > len(data):
      raise ValueError('GPG MPI data too short.')
    i += size
  return i


def skip_gpg_key_pstrings(data, i, pstring_count):
  while pstring_count > 0:
    # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.6.6
    pstring_count -= 1
    if i >= len(data):
      raise ValueError('GPG key pstring too short.')
    size, = struct.unpack('>B', data[i : i + 1])
    i += 1
    if size == 0 or size == 0xff:
      raise ValueError('Bad GPG key pstring size: 0x%x' % size)
    if i + size > len(data):
      raise ValueError('GPG key pstring too short.')
    i += size
  return i


def get_gpg_public_key_packet_size(data, i=0):
  """Input is private key packet data or public key packet data."""
  if i + 6 > len(data):
    raise ValueError('EOF in GPG key packet header.')
  version, creation_time, public_key_algo = struct.unpack('>BLB', data[i : i + 6])
  if version != 4:
    raise ValueError('Unsupported GPG key packet version: %d' % version)
  i += 6
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.6
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-9.1
  if public_key_algo == 1:  # RSA.
    i = skip_gpg_mpis(data, i, 2)
  elif public_key_algo == 17:  # DSA.
    i = skip_gpg_mpis(data, i, 4)
  elif public_key_algo == 16:  # Elgamal.
    i = skip_gpg_mpis(data, i, 3)
  elif public_key_algo == 18:  # ECDH.
    # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.6.6
    i = skip_gpg_key_pstrings(data, i, 1)
    i = skip_gpg_mpis(data, i, 1)
    i = skip_gpg_key_pstrings(data, i, 1)
  elif public_key_algo in (19, 22):  # (ECDSA, EdDSA)
    i = skip_gpg_key_pstrings(data, i, 1)
    i = skip_gpg_mpis(data, i, 1)
  else:
    raise ValueError('Unknown GPG public key algo: %d' % public_key_algo)
  return i


def build_gpg_export_key_data(d, d_sub, is_public, hash_name='sha256', _bbe=bbe):
  """Returns bytes in `gpg --export-secret-key ...' format, can be imported with `gpg --import <...'"""
  # TODO(pts): Add expiry. Now these keys never expire.
  private_key_packet_data = build_gpg_rsa_private_key_packet_data(d)
  public_key_packet_data = private_key_packet_data[:get_gpg_public_key_packet_size(private_key_packet_data)]
  key_id20 = build_gpg_key_id20(public_key_packet_data)
  if isinstance(d_sub, bytes):
    private_subkey_packet_data = d_sub
  elif isinstance(d_sub, dict):
    private_subkey_packet_data = build_gpg_rsa_private_key_packet_data(d_sub)
    # True but slow: assert build_gpg_rsa_public_key_packet_data(d_sub) == private_subkey_packet_data[:get_gpg_public_key_packet_size(private_subkey_packet_data)]
  elif d_sub is None:  # Build it without a subkey.  It is unusual to have no subkey, but we can do it.
    userid_cert_signature_packet_data = build_gpg_userid_cert_rsa_signature_packet_data(
        d, hash_name, public_key_packet_data, key_id20, key_flags=GPG_KEY_FLAG_CERTIFY | GPG_KEY_FLAG_SIGN | GPG_KEY_FLAG_ENCRYPT)
    output = []
    if is_public:
      output.extend((build_gpg_packet_header(6, len(public_key_packet_data)), public_key_packet_data))
    else:
      output.extend((build_gpg_packet_header(5, len(private_key_packet_data)), private_key_packet_data))
    output.extend((build_gpg_packet_header(13, len(d['comment'])), d['comment'],
                   build_gpg_packet_header(2, len(userid_cert_signature_packet_data)), userid_cert_signature_packet_data))
    return _bbe.join(output)
  else:
    raise TypeError('Bad subkey type: %r' % type(d_sub))
  userid_cert_signature_packet_data = build_gpg_userid_cert_rsa_signature_packet_data(d, hash_name, public_key_packet_data, key_id20)
  public_subkey_packet_data = private_subkey_packet_data[:get_gpg_public_key_packet_size(private_subkey_packet_data)]
  subkey_signature_packet_data = build_gpg_subkey_rsa_signature_packet_data(d, public_subkey_packet_data, hash_name, public_key_packet_data, key_id20)
  output = []
  if is_public:
    output.extend((build_gpg_packet_header(6, len(public_key_packet_data)), public_key_packet_data))
  else:
    output.extend((build_gpg_packet_header(5, len(private_key_packet_data)), private_key_packet_data))
  output.extend((build_gpg_packet_header(13, len(d['comment'])), d['comment'],
                 build_gpg_packet_header(2, len(userid_cert_signature_packet_data)), userid_cert_signature_packet_data))
  if is_public:
    output.extend((build_gpg_packet_header(14, len(public_subkey_packet_data)), public_subkey_packet_data))
  else:
    output.extend((build_gpg_packet_header(7, len(private_subkey_packet_data)), private_subkey_packet_data))
  output.extend((build_gpg_packet_header(2, len(subkey_signature_packet_data)), subkey_signature_packet_data))
  return _bbe.join(output)


def is_gpg_userid(comment, _bbemailstart=bb(' <'), _bbemailend=bb('>'), _bbnl=bbnl):
  # Example good comment: bb('Test Real Name 6 (Comment 6) <testemail6@email.com>').
  return comment and (comment.startswith(_bbemailstart[1:]) or _bbemailstart in comment) and comment.endswith(_bbemailend) and _bbnl not in comment


# --- Serialization and parsing.


def serialize_rsa_der(d, is_public):
  # DER and PEM generators (ASN.1): https://0day.work/how-i-recovered-your-private-key-or-why-small-keys-are-bad/
  if is_public:
    # https://stackoverflow.com/a/29707204
    return der_value((d['modulus'], d['public_exponent']))
  else:
    return der_value((0, d['modulus'], d['public_exponent'], d['private_exponent'], d['prime1'], d['prime2'], d['exponent1'], d['exponent2'], d['coefficient']))


def parse_rsa_der_numbers(data, i=0, j=None):
  if j is None:
    j = len(data)
  d = {}
  i, d['modulus'] = parse_der_uint(data, i, j)
  i, d['public_exponent'] = parse_der_uint(data, i, j)
  i, d['private_exponent'] = parse_der_uint(data, i, j)
  if i < j:
    i, d['prime1'] = parse_der_uint(data, i, j)
    # Stop parsing here, we can calculate the rest.
  return d


OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'  # rsaEncryption.
DER_OID_RSA_ENCRYPTION = der_oid(OID_RSA_ENCRYPTION)
DER2_RSA_SEQUENCE_DATA = DER_OID_RSA_ENCRYPTION + der_value(None)


def parse_rsa_der_header(data, i=0, _bb30=bb('\x30')):
  if data[i : i + 1] != _bb30:
    raise ValueError('Expected der input.')
  i0 = i
  i, size = parse_der_sequence_header(data, i)
  j = i + size
  i = parse_der_zero(data, i)
  if data[i : i + 1] == _bb30:  # der2.
    i, size = parse_der_sequence_header(data, i)
    if data[i : i + size] != DER2_RSA_SEQUENCE_DATA:
      raise ValueError('Unsupported der2 sequence.')
    i += size
    i, size = parse_der_bytes_header(data, i)
    if len(data) < i + size:
      raise ValueError('EOF in der2 bytes.')
    j = i + size
    i0 = i
    i, size = parse_der_sequence_header(data, i)
    if i > j:
      raise ValueError('der2 too long.')
    i = parse_der_zero(data, i)
    if i > j:
      raise ValueError('der2 too long.')
  return i, j, i0


def parse_rsa_pem(data,
                  _bbe=bbe, _bbd=bb('-'), _bbbegin=bb('\n-----BEGIN '), _bbend=bb('\n-----END '), _bbnl=bbnl, _bbcolon=bb(':'),
                  _bbencrypted=bb('ENCRYPTED '), _bbrsapk=bb('RSA PRIVATE KEY-----\n'), _bbopensshpk=bb('OPENSSH PRIVATE KEY-----\n'), _bbpk=bb('PRIVATE KEY-----\n')):
  # PEM format. Used by both `openssl rsa' (and web servers) and OpenSSH.
  if data.startswith(_bbbegin[1:]):
    i = len(_bbbegin) - 1
  else:
    i = 0
    while data[i : i + 1].isspace():
      i += 1
    if i == len(data):
      raise ValueError('RSA key file contains only whitespace.')
    if has_hexa_header(data, i):
      return parse_rsa_hexa(data, i)
    if data[i : i + 1] != _bbd:
      raise ValueError('dash not found in pem.')
    i = data.find(_bbbegin, i)  # TODO(pts): Treat \r as \n.
    if i < 0:
      raise ValueError('BEGIN not found in pem.')
    i += len(_bbbegin)
  j = data.find(_bbnl, i + 1)
  if j < 0:
    raise ValueError('EOF in pem BEGIN line.')
  is_openssh = False
  if data[i : i + len(_bbrsapk)] == _bbrsapk:
    pass
  elif data[i : i + len(_bbpk)] == _bbpk:
    pass
  elif data[i : i + len(_bbopensshpk)] == _bbopensshpk:
    is_openssh = True
  elif data[i : i + len(_bbencrypted)] == _bbencrypted:
    raise ValueError('Encrypted (passphrase-protected) pem key not supported.')
  else:
    raise ValueError('Unsupported pem type: %r' % data[i - len(_bbbegin) + 1 : j])
  i, j = j, data.find(_bbd, j)
  if j <= 0:
    raise ValueError('End of pem not found.')
  j -= 1
  if data[j : j + len(_bbend)] != _bbend:
    raise ValueError('END not found in pem.')
  data = _bbe.join(data[i : j].replace(_bbnl, _bbe).split())
  if _bbcolon in data:
    raise ValueError('Encrypted (passphrase-protected) pem key (in data) not supported.')
  # TODO(pts): Check for disallowed characters (e.g. ~) in data.
  data = binascii.a2b_base64(data)
  if is_openssh:
    return parse_rsa_opensshbin(data)
  return data


def parse_rsa_ssh_numbers(data, i=0, j=None, format='dropbear'):
  if j is None:
    j = len(data)
  d = {}
  # OpenSSH order:   modulus,         public_exponent, private_exponent, coefficient, prime1, prime2, comment (binary), padding123.
  # Dropbear order:  public_exponent, modulus,         private_exponent, prime1, prime2.
  i, d['modulus'] = parse_be32size_uint(data, i, j)
  i, d['public_exponent'] = parse_be32size_uint(data, i, j)
  if d['modulus'] > d['public_exponent']:
    if format and format != 'opensshsingle':
      raise ValueError('modulus vs public_exponent indicate opensshsingle input format, got: %r' % format)
    i, d['private_exponent'] = parse_be32size_uint(data, i, j)
    i, unused_coefficient = parse_be32size_uint(data, i, j)
    i, d['prime1'] = parse_be32size_uint(data, i, j)
    # We don't need prime2.
    i, unused_prime2 = parse_be32size_uint(data, i, j)
    i, d['comment'] = parse_be32size_bytes(data, i, j)
    if not d['comment']:
      del d['comment']
  else:
    if format and format != 'dropbear':
      raise ValueError('modulus vs public_exponent indicate dropbear input format, got: %r' % format)
    d['modulus'], d['public_exponent'] = d['public_exponent'], d['modulus']
    i, d['private_exponent'] = parse_be32size_uint(data, i, j)
    i, d['prime1'] = parse_be32size_uint(data, i, j)
    # prime2 is the last number in the file, but we don't need it.
    # i, d['prime2'] = parse_be32size_uint(data, i, j)
  return d


bbsshrsa = bb('\0\0\0\7ssh-rsa')  # TODO(pts): Uppercase variable names.


def parse_rsa_opensshld(data, i=0, _bb00=bb('\0\0'), _bbsshrsa=bbsshrsa):
  """Parses OpenSSH length-delimited plaintext RSA private key."""
  i1 = i + 12 + len(_bbsshrsa)
  if not (data[i : i + 2] == _bb00 and data[i + 12 : i1] == _bbsshrsa):
    raise ValueError('opensshld signature not found.')
  checkint1, checkint2 = struct.unpack('>LL', data[i + 4 : i + 12])
  if checkint1 != checkint2:
    raise ValueError('Mismatch in opensshld checkints.')
  d = parse_rsa_ssh_numbers(data, i1, j=None, format='opensshsingle')
  d['checkint'] = checkint1
  return d


def serialize_rsa_dropbear(d, _bbe=bbe, _bbsshrsa=bbsshrsa):
  return _bbe.join((_bbsshrsa, be32size_value(d['public_exponent']), be32size_value(d['modulus']), be32size_value(d['private_exponent']), be32size_value(d['prime1']), be32size_value(d['prime2'])))


def serialize_rsa_opensshsingle(d, _bbe=bbe, _bbsshrsa=bbsshrsa, _bbpad15=bb('\1\2\3\4\5\6\7\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')):
  output = [_bbsshrsa, be32size_value(d['modulus']), be32size_value(d['public_exponent']), be32size_value(d['private_exponent']), be32size_value(d['coefficient']), be32size_value(d['prime1']), be32size_value(d['prime2']), be32size_value(d.get('comment', _bbe))]
  size = sum(map(len, output))
  if size & 15:
    output.append(_bbpad15[:-size & 15])
  return _bbe.join(output)


def serialize_rsa_opensshld(d):
  data = serialize_rsa_opensshsingle(d)
  checkint = d.get('checkint', 0x43484B49)  # 'CHKI'.
  return struct.pack('>LLL', len(data) + 8, checkint, checkint) + data


bbopensshbin = bb('openssh-key-v1\0')


def parse_rsa_opensshbin(data, i=0, _bbsshrsa=bbsshrsa, _bbopensshbin=bbopensshbin, _bbnone=bb('none')):
  if data[i : i + len(_bbopensshbin)] != _bbopensshbin:
    raise ValueError('opensshbin signature not found.')
  i += len(_bbopensshbin)
  j = len(data)
  i, cipher = parse_be32size_bytes(data, i, j)
  if cipher != _bbnone:
    raise ValueError('Encrypted (passphrase-protected) opensshbin key not supported.')
  i, kdf = parse_be32size_bytes(data, i, j)  # Usually it's also b'none'.
  i, kdfoptions = parse_be32size_bytes(data, i, j)  # Usually it's b''.
  if i + 4 > j:
    raise ValueError('EOF in opensshbin key count.')
  key_count, = struct.unpack('>L', data[i : i + 4])
  i += 4
  if key_count != 1:
    raise ValueError('Unsupported opensshbin key count: %d' % key_count)
  if i + 4 > j:
    raise ValueError('EOF in opensshbin public key size.')
  public_key_size, = struct.unpack('>L', data[i : i + 4])
  i += 4
  j = i + public_key_size
  i, algo = parse_be32size_bytes(data, i, j)
  if algo != _bbsshrsa[4:]:
    raise ValueError('Unsupported opensshbin non-RSA key.')
  i, public_exponent = parse_be32size_uint(data, i, j)
  i, modulus = parse_be32size_uint(data, i, j)
  # We could check `i == j' here, but we don't bother.
  d = parse_rsa_opensshld(data, j)
  if d['modulus'] != modulus:
    raise ValueError('opensshbin modulus mismatch in keys.')
  if d['public_exponent'] != public_exponent:
    raise ValueError('opensshbin public_exponent mismatch in keys.')
  return d


def serialize_rsa_opensshbin(d, _bbopensshbin=bbopensshbin, _bbsshrsa=bbsshrsa, _bbe=bbe, _bbnonestr=bb('\0\0\0\4none'), _bbemptystr=bb('\0\0\0\0'), _bbonekey=bb('\0\0\0\1')):
  # https://github.com/openssh/openssh-portable/blob/20819b962dc1467cd6fad5486a7020c850efdbee/PROTOCOL.key#L10-L19
  public_key_data = _bbe.join((_bbsshrsa, be32size_value(d['public_exponent']), be32size_value(d['modulus'])))
  private_key_data = serialize_rsa_opensshld(d)
  return _bbe.join((_bbopensshbin, _bbnonestr, _bbnonestr, _bbemptystr, _bbonekey, struct.pack('>L', len(public_key_data)), public_key_data, private_key_data))


def serialize_rsa_opensshbin(d, _bbopensshbin=bbopensshbin, _bbsshrsa=bbsshrsa, _bbe=bbe, _bbnonestr=bb('\0\0\0\4none'), _bbemptystr=bb('\0\0\0\0'), _bbonekey=bb('\0\0\0\1')):
  # https://github.com/openssh/openssh-portable/blob/20819b962dc1467cd6fad5486a7020c850efdbee/PROTOCOL.key#L10-L19
  public_key_data = _bbe.join((_bbsshrsa, be32size_value(d['public_exponent']), be32size_value(d['modulus'])))
  private_key_data = serialize_rsa_opensshld(d)
  return _bbe.join((_bbopensshbin, _bbnonestr, _bbnonestr, _bbemptystr, _bbonekey, struct.pack('>L', len(public_key_data)), public_key_data, private_key_data))


bbopensshbegin = bb('-----BEGIN OPENSSH PRIVATE KEY-----\n')
bbopensshend = bb('\n-----END OPENSSH PRIVATE KEY-----\n')


def serialize_rsa_openssh(d, _bbopensshbegin=bbopensshbegin, _bbopensshend=bbopensshend, _bbe=bbe):
  return _bbe.join((_bbopensshbegin, base64_encode(serialize_rsa_opensshbin(d), 70), _bbopensshend))


def serialize_rsa_sshpublic(d, _bbe=bbe, _bbsshrsa=bbsshrsa, _bbsshrsasp=bb('ssh-rsa '), _bbnl=bbnl, _bbsp=bb(' '), _bbrr=bb('\r')):
  data = _bbe.join((_bbsshrsa, be32size_value(d['public_exponent']), be32size_value(d['modulus'])))
  return _bbe.join((_bbsshrsasp, binascii.b2a_base64(data).rstrip(_bbnl), _bbsp, d.get('comment', _bbe).replace(_bbnl, _bbsp).replace(_bbrr, _bbsp), _bbnl))


bbmsblob = struct.pack('<LL4s', 0x207, 0xa400, bb('RSA2'))


def serialize_rsa_msblob(d, _bbe=bbe, _bbz=bbz, _bbmsblob=bbmsblob):
  if d['public_exponent'] >> 32:
    raise ValueError('public_exponent too large for msblob.')
  def le_padded(value, size):
    value = uint_to_any_be(value)[::-1]
    psize = size - len(value)
    if psize < 0:
      raise ValueError('msblob value too large.')  # Shouldn't happen.
    return value + _bbz * psize
  modulus_bytes = uint_to_any_be(d['modulus'])[::-1]
  size = len(modulus_bytes)
  if size >> 29:
    raise ValueError('modulus too large for msblob.')
  hsize = (size + 1) >> 1
  return _bbe.join((
      _bbmsblob, struct.pack('<LL', size << 3, d['public_exponent']), modulus_bytes,
      le_padded(d['prime1'], hsize), le_padded(d['prime2'], hsize),
      le_padded(d['exponent1'], hsize), le_padded(d['exponent2'], hsize),
      le_padded(d['coefficient'], hsize),
      le_padded(d['private_exponent'], size)))


HEXA_KEYS = ('modulus', 'public_exponent', 'private_exponent', 'prime1', 'prime2', 'exponent1', 'exponent2', 'coefficient', 'comment', 'checkint', 'creation_time')
HEXA_ALIASES = {'n': 'modulus', 'e': 'public_exponent', 'd': 'private_exponent', 'q': 'prime1', 'p': 'prime2', 'u': 'coefficient'}


def has_hexa_header(data, i, _bbu=bb('_'), _bbeq=bb('=')):
  i0 = i
  while data[i : i + 1].isalnum() or data[i : i + 1] == _bbu:
    i += 1
  if not (data[i : i + 1] .isspace() or data[i : i + 1] == _bbeq):
    return False
  key = aa(data[i0 : i])
  key = HEXA_ALIASES.get(key, key)
  return key in HEXA_KEYS


def parse_rsa_hexa(data, i, _bbu=bb('_'), _bbeq=bb('=')):
  d, j = {}, len(data)
  while i < j:
    i0 = i
    while data[i : i + 1].isalnum() or data[i : i + 1] == _bbu:
      i += 1
    i1 = i
    while data[i : i + 1].isspace():
      i += 1
    key = aa(data[i0 : i1])
    if data[i : i + 1] != _bbeq:
      raise ValueError('Assignment expected after hexa key %r.' % key)
    i += 1
    if key in d:
      raise ValueError('Duplicate assignment key %r.' % key)
    if key != 'comment':
      key = HEXA_ALIASES.get(key, key)
      if key not in HEXA_KEYS:
        raise ValueError('Unknown assignment key: %r' % key)
    while data[i : i + 1].isspace():
      i += 1
    i2 = i
    while j > i and not data[i : i + 1].isspace():
      i += 1
    value = data[i2 : i]
    if key == 'comment':
      value = parse_repr_bytes(value.strip())
    else:
      try:
        value = int(value, 0)
      except ValueError:
        value = None
      if value is None:
        raise ValueError('Syntax error in integer for assignment key %r: %r' % (key, data[i2 : i]))
      if value < 0:
        raise ValueError('Negative integer for assignment key %r.' % key)
    d[key] = value
    if i == j:
      break
    i3 = i
    while data[i : i + 1].isspace():
      i += 1
    if i == i3:
      raise ValueError('Missing whitespace after assignment of key %r.' % key)
  return d


def serialize_rsa_hexa(d, _bbassign=bb(' = '), _bbnl=bbnl, _bbe=bbe, _bbpx=bb('%x'), _bb0=bb('0')):
  """Serializes hexa: hexadecimal assignment."""
  output = []
  for key in HEXA_KEYS:
    if key not in d:
      if key not in ('comment', 'checkint', 'creation_time'):
        raise KeyError('RSA key missing: %r' % key)
      continue
    value = d[key]
    output.append(bb(key))
    output.append(_bbassign)
    append_portable_repr(output, value)
    output.append(_bbnl)
  return _bbe.join(output)


def parse_rsa_msblob_numbers(data, i=0, j=None):
  if j is None:
    j = len(data)
  i, bit_size = parse_msblob_uint(data, i, j, 4)
  size = (bit_size + 7) >> 3
  hsize = (bit_size + 15) >> 4
  d = {}
  i, d['public_exponent'] = parse_msblob_uint(data, i, j, 4)
  i, d['modulus'] = parse_msblob_uint(data, i, j, size)
  i, d['prime1'] = parse_msblob_uint(data, i, j, hsize)
  i += hsize << 2  # We don't need these.
  if j >= i + size and len(data) >= i + size:  # For speedup.
    i, d['private_exponent'] = parse_msblob_uint(data, i, j, size)
    r, q = divmod(d['modulus'], d['prime1'] or 1)
    if not (q == 0 and r > 1 and d['prime1'] > 1 and d['public_exponent'] * d['private_exponent'] % ((d['prime1'] - 1) * (r - 1)) == 1):
      del d['private_exponent']  # Corrupted, don't use it.
  return d


GPG_RSA_KEYS_AA = 'nedpqu'
GPG_RSA_KEYS = bb(GPG_RSA_KEYS_AA)


def parse_rsa_gpg22_numbers(data, i=0, j=None, _bbop=bb('('), _bbcp=bb(')'), _bbu=bb('_'), _bbkeys=GPG_RSA_KEYS):
  if j is None:
    j = len(data)
  d = {}
  while 1:
    c = data[i : i + 1]
    if c == _bbcp:
      break
    elif c != _bbop:
      if not c:
        raise ValueError('EOF in gpg22 entry start.')
      raise ValueError('Paren expected in gpg22 entry, got: %r' % c)
    i += 1
    i, i0 = parse_gpg22_bytes(data, i, j, 'key')
    key = data[i0 : i]
    if len(key) != 1 or key not in _bbkeys:
      raise ValueError('Bad gpg22 key: %r' % key)
    key = aa(key)
    i, value = parse_gpg22_uint(data, i, j)
    if not (i < j and i < len(data) and data[i : i + 1] == _bbcp):
      raise ValueError('Close paren expected in gpg22 entry.')
    i += 1
    d[key] = value
  # Typically d has all of GPG_RSA_KEYS now, but get_rsa_private_key will
  # raise an exception if it doesn't.
  return d


# Format used by GPG 2.2.
# ~/.gnupg/private-keys-v1.d/*.key
bbgpg22 = bb('(11:private-key(3:rsa(')
bbgpg22prot = bb('(21:protected-private-key(')


def serialize_rsa_gpg22(d, _bbe=bbe, _bbgpg22=bbgpg22, _bbgpg22close=bb(')))')):
  output = [_bbgpg22]
  append_gpg22_uint(output, bb('1:n'), d['modulus'])
  append_gpg22_uint(output, bb(')(1:e'), d['public_exponent'])
  append_gpg22_uint(output, bb(')(1:d'), d['private_exponent'])
  append_gpg22_uint(output, bb(')(1:p'), d['prime2'])
  append_gpg22_uint(output, bb(')(1:q'), d['prime1'])
  append_gpg22_uint(output, bb(')(1:u'), d['coefficient'])
  output.append(_bbgpg22close)
  return _bbe.join(output)


def serialize_rsa_gpg23(d, _bbe=bbe):
  # https://lists.gnupg.org/pipermail/gnupg-devel/2017-December/033295.html
  # GPG 2.3 will probably insert line breaks after 64 columns. It will
  # also insert other headers (in addition to `Key: ').
  return _bbe.join((
      bb('Key: (private-key\n  (rsa\n  (n #'), gpg23_uint(d['modulus']),
      bb('#)\n  (e #'), gpg23_uint(d['public_exponent']),
      bb('#)\n  (d #'), gpg23_uint(d['private_exponent']),
      bb('#)\n  (p #'), gpg23_uint(d['prime2']),
      bb('#)\n  (q #'), gpg23_uint(d['prime1']),
      bb('#)\n  (u #'), gpg23_uint(d['coefficient']),
      bb('#)\n  ))\n')))


def has_gpg23_header(data, i=0,  _bbd=bb('-'), _bbcsp=bb(': ')):
  c = data[i : i + 1]
  if not (c.isalpha() and c.upper() == c):
    return False
  while data[i : i + 1].isalpha() or data[i : i + 1] == _bbd:
    i += 1
  return data[i : i + 2] == _bbcsp


# Format used by GPG 2.3.
# ~/.gnupg/private-keys-v1.d/*.key
bbgpg23 = bb('(private-key(rsa(')
bbgpg23priv = bb('(private-key(')
bbgpg23prot = bb('(protected-private-key(')


def parse_rsa_gpg23(data, i=0,
                    _bbkey=bb('\nKey: '), _bbnl=bbnl, _bbe=bbe, _bbnlsp=bb('\n '), _bbsp=bb(' '), _bbd=bb('-'),
                    _bbop=bb('('), _bbcp=bb(')'), _bbu=bb('_'), _bbkeys=GPG_RSA_KEYS,
                    _bbgpg23=bbgpg23, _bbgpg23priv=bbgpg23priv, _bbgpg23prot=bbgpg23prot):
  if not has_gpg23_header(data, i):
    raise ValueEror('Expected gpg23 header.')
  if i == 0 and data.startswith(_bbkey[1:]):
    i += len(_bbkey) - 1
  else:
    i = data.find(_bbkey)
    if i < 0:
      raise ValueError('Missing gpg23 key header.')
    i += len(_bbkey)
  data = data[i:].replace(_bbnlsp, _bbe)
  i = data.find(_bbnl)
  if i < 0:
    raise ValueError('Incomplete gpg23 key header.')
  data = _bbe.join(data[:i].replace(_bbsp, _bbe).split())
  if not data.startswith(bbgpg23):
    if data.startswith(bbgpg23priv):
      raise ValueError('Non-RSA gpg23 key not supported.')
    if data.startswith(bbgpg23prot):
      raise ValueError('Encrypted (passphrase-protected) gpg23 key not supported.')
    if data[:1] != _bbop:
      raise ValueError('Expected paren in gpg23 key header.')
    i0 = i = 1
    while data[i : i + 1].isalpha() or data[i : i + 1] == _bbd:
      i += 1
    if data[i : i + 1] != _bbop:
      raise ValueError('Expected second paren in gpg23 key header.')
    raise ValueError('gpg23 key format not supported: %s' % aa(data[i0 : i]))
  i, d, j = len(bbgpg23) - 1, {}, len(data)
  while 1:
    c = data[i : i + 1]
    if c == _bbcp:
      break
    elif c != _bbop:
      if not c:
        raise ValueError('EOF in gpg23 entry start.')
      raise ValueError('Paren expected in gpg23 entry, got: %r' % c)
    i += 1
    i0 = i
    while data[i : i + 1].isalpha() or data[i : i + 1] == _bbd:
      i += 1
    key = data[i0 : i]
    if len(key) != 1 or key not in _bbkeys:
      raise ValueError('Bad gpg23 key: %r' % key)
    key = aa(key)
    i, value = parse_gpg23_uint(data, i, j)
    if data[i : i + 1] != _bbcp:
      raise ValueError('Close paren expected in gpg23 entry.')
    i += 1
    d[key] = value
  # Typically d has all of GPG_RSA_KEYS now, but get_rsa_private_key will
  # raise an exception if it doesn't.
  return d


bbgpglists = (bb('gpg: '), bb('# off='), bb(':secret key packet:'))


def parse_rsa_gpglist(data, i, keyid, _bbnl=bbnl, _bbcr=bb('\r'), _bbe=bbe, _bbcolonsp=bb(': '), _bbspcomma=bb(', '), _bbsp=bb(' '), _bbclsqb=bb(']'), _bb1=bb('1'),
                      _bbskps=(bb(':secret key packet:'), bb(':secret sub key packet:'), bb(':public key packet:'), bb(':public sub key packet:')), _bbbits=bb(' bits]'),
                      _bbtab=bb('\t'), _bbversion=bb('\tversion '), _bbpkey=bb('pkey['), _bbskey=bb('skey['), _bbprotected=bb('protected'), _bbsecmem=bb('gpg: secmem usage: ')):
  """Parses output of: gpg --export-secret-key ... |
  gpg --list-packets -vvv --debug 0x2"""
  import sys
  data = data[i:]
  if keyid is not None:
    keyid = keyid.upper()

  def yield_dicts():
    state = 0
    d = {}
    preline = _bbe
    for line in data.replace(_bbcr, _bbe).split(_bbnl):
      line, preline = preline + line.rstrip(), _bbe
      i = line.find(_bbsecmem)  # Sometimes flushed into the middle of the key hex digits.
      if i >= 0:
        preline += line[:i]
        continue
      if line in _bbskps:
        if d:
          yield d
        d = {}
        state = 1
      elif state == 1:
        if not line.startswith(_bbtab):
          state = 2
        elif line.startswith(_bbversion):
          for item in line[1:].split(_bbspcomma):
            i = item.find(_bbsp)
            if i > 0:
              key, value = item[:i], item[i + 1:]
              try:
                d[aa(key)] = value
              except ValueError:
                pass  # Ignore non-ASCII keys.
        else:
          i = line.find(_bbcolonsp)
          if i > 0:
            key, value = line[1 : i], line[i + 2:]
            if (key.startswith(_bbpkey) or key.startswith(_bbskey)) and key.endswith(_bbclsqb):
              key0, key = key, key[5 : -1]
              if d.get('algo') == _bb1:  # RSA.
                try:
                  key = int(key)
                except ValueError:
                  key = None
                if key is not None and 0 <= key < 4:
                  if _bbprotected in value:
                    d['is_protected'] = True
                  else:
                    if value.endswith(_bbbits):
                      raise ValueError('Missing hex digits in gpglist RSA uint, use this to dump: gpg --list-packets --debug 0x2')
                    try:
                      value = int(value, 16)
                    except ValueError:
                      value = None
                    if value is None:
                      raise ValueError('Bad hex digits in key: %r' % key0)
                    d[GPG_RSA_KEYS_AA[key]] = value
            else:
              try:
                key = aa(key)
              except ValueError:
                key = ''  # Ignore non-ASCII keys.
              if key == 'keyid':
                try:
                  int(value, 16)
                except ValueError:
                  value = None
                if value is None:
                  raise ValueError('Syntax error in keyid: %r' % value)
                value = aa(value).upper()
                d[key] = value
              elif 'protect' in key:
                d['is_protected'] = True
    if d:
      yield d

  dk = None
  for d in yield_dicts():
    if 'keyid' in d:
      if d.get('algo') != _bb1:
        sys.stderr.write('info: ignoring non-RSA key: -keyid %s\n' % d['keyid'])
      elif 'n' in d and 'e' in d and 'd' not in d:
        if d.get('is_protected'):
          sys.stderr.write('info: ignoring protected RSA secret key: -keyid %s\n' % d['keyid'])
        else:
          sys.stderr.write('info: ignoring RSA public key: -keyid %s\n' % d['keyid'])
      elif not ('n' in d and 'e' in d and 'd' in d and 'p' in d):
        sys.stderr.write('info: ignoring partial RSA key: -keyid %s\n' % d['keyid'])
      else:
        d.pop('algo', None)
        d.pop('version', None)
        if d['keyid'] == keyid:
          dk = d
          sys.stderr.write('info: using RSA private key: -keyid %s\n' % d['keyid'])
        else:
          sys.stderr.write('info: found RSA private key: -keyid %s\n' % d['keyid'])
  if keyid is None:
    raise ValueError('Please specify -keyid ... to select GPG key.')
  elif dk is None:
    raise ValueError('Specified -keyid key not found: %r' % keyid)
  return dk


def convert_rsa_data(d, format='pem', effort=None, keyid=None,
                     _bbe=bbe, _bbd=bb('-'), _bb30=bb('\x30'), _bbsshrsa=bbsshrsa, _bbopensshbin=bbopensshbin, _bbmsblob=bbmsblob, _bbgpg22=bbgpg22, _bbgpg22prot=bbgpg22prot, _bbgpglists=bbgpglists,
                     _bb00=bb('\0\0'), _bbz=bbz):
  if isinstance(d, bytes):
    data = d
    if data.startswith(_bbsshrsa):
      # Dropbear SSH RSA private key format, output of:
      # dropbearconvert openssh dropbear id_rsa id_rsa.dropbear
      # This can also be OpenSSH RSA private key format (usually not
      # observed in the wild).
      d = parse_rsa_ssh_numbers(data, len(_bbsshrsa), j=None, format=None)
    elif data.startswith(_bbopensshbin):
      d = parse_rsa_opensshbin(data)
    elif data.startswith(_bbmsblob):
      # Microsoft SSH RSA private key format, output of:
      # openssl rsa -outform msblob -in key.pem -out key.msblob
      d = parse_rsa_msblob_numbers(data, len(_bbmsblob))
    elif data.startswith(_bbgpg22):
      d = parse_rsa_gpg22_numbers(data, len(_bbgpg22) - 1)
    elif data.startswith(_bbgpg22prot):
      raise ValueError('Encrypted (passphrase-protected) gpg22 key not supported.')
    elif has_hexa_header(data, 0):
      d = parse_rsa_hexa(data, 0)
    elif has_gpg23_header(data):
      d = parse_rsa_gpg23(data)
    elif [1 for prefix in _bbgpglists if data.startswith(prefix)]:
      d = parse_rsa_gpglist(data, 0, keyid)
    elif data.startswith(_bb00) and data[12 : 12 + len(_bbsshrsa)] == _bbsshrsa:
      d = parse_rsa_opensshld(data)
    else:
      # TODO(pts): Add support for RSA private keys in GPG `gpg
      # --export-secret-keys', selected by key ID.
      if data.startswith(_bbd) or data[:1].isspace():  # PEM or hexa format.
        data = parse_rsa_pem(data)  # Parses ('pem', 'pem2', 'openssh', 'hexa'-with-whitespace).
      elif data[:1] != _bb30:
        raise ValueError('Unknown RSA private key input format.')
      if isinstance(data, dict):
        d, data = data, None
      else:
        i, j, i0 = parse_rsa_der_header(data)  # DER format.
        if effort is None or effort >= 2 or format not in ('der', 'pem', 'der2', 'pem2'):
          d = parse_rsa_der_numbers(data, i, j)
        else:
          d, data = False, data[i0 : j]
  if d is not False:
    assert isinstance(d, dict)
    if not is_rsa_private_key_complete(d, effort):
      d = get_rsa_private_key(**d)
    if format == 'dict':
      return d
    if format == 'dropbear':
      return serialize_rsa_dropbear(d)
    if format == 'openssh':
      return serialize_rsa_openssh(d)
    if format == 'sshpublic':
      return serialize_rsa_sshpublic(d)
    if format == 'opensshsingle':
      return serialize_rsa_opensshsingle(d)
    if format == 'opensshld':
      return serialize_rsa_opensshld(d)
    if format == 'opensshbin':
      return serialize_rsa_opensshbin(d)
    if format == 'msblob':
      return serialize_rsa_msblob(d)
    if format == 'hexa':
      return serialize_rsa_hexa(d)
    if format == 'gpg22':
      return serialize_rsa_gpg22(d)
    if format == 'gpg23':
      return serialize_rsa_gpg23(d)
    if format == 'gpg':
      return build_gpg_export_key_data(d, d.get('sub'), is_public=False)
    if format == 'gpgpublic':
      return build_gpg_export_key_data(d, d.get('sub'), is_public=True)
    if format in ('pkcs1derpublic', 'pkcs1pempublic', 'pkcs8derpublic', 'pkcs8pempublic'):
      d, data = None, serialize_rsa_der(d, is_public=True)
      if format.startswith('pkcs8'):
        data = der_value(((DER_OID_RSA_ENCRYPTION, None), der_bytes_bit(_bbz + data)))
      if format.endswith('derpublic'):
        return data
      elif format.startswith('pkcs8'):
        return _bbe.join((bb('-----BEGIN PUBLIC KEY-----\n'), base64_encode(data), bb('\n-----END PUBLIC KEY-----\n')))
      else:
        return _bbe.join((bb('-----BEGIN RSA PUBLIC KEY-----\n'), base64_encode(data), bb('\n-----END RSA PUBLIC KEY-----\n')))
    if format not in ('der', 'pem', 'der2', 'pem2', 'pcks1der', 'pcks1', 'pkcs1pem', 'pkcs8der', 'pkcs8', 'pkcs8pem'):
      raise ValueError('Unknown RSA key format: %r' % (format,))
    d, data = None, serialize_rsa_der(d, is_public=False)
  if not (isinstance(data, bytes) and d is None):
    raise TypeError
  if format in ('der', 'pkcs1der'):
    # PKCS #1 ASN.1 RSA private key: https://tools.ietf.org/html/rfc8017#appendix-A.1.2
    # DER: https://en.wikipedia.org/wiki/X.690#DER_encoding
    return data
  if format in ('pem', 'pkcs1', 'pkcs1pem'):
    # PKCS #1 ASN.1 RSA private key: https://tools.ietf.org/html/rfc8017#appendix-A.1.2
    # PEM: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
    # https://linuxsecurity.com/resource_files/cryptography/ssl-and-certificates.html
    # This is the ``traditional'' RSA private key format used by OpenSSL,
    # it's also called as the ``SSLeay format''. According to
    # https://crypto.stackexchange.com/a/47433/ , there is no well-known
    # standard.
    return _bbe.join((bb('-----BEGIN RSA PRIVATE KEY-----\n'), base64_encode(data), bb('\n-----END RSA PRIVATE KEY-----\n')))
  data = der_value((0, (DER_OID_RSA_ENCRYPTION, None), der_bytes(data)))
  if format in ('der2', 'pkcs8der'):
    # PKCS #8: https://en.wikipedia.org/wiki/PKCS_8
    # DER: https://en.wikipedia.org/wiki/X.690#DER_encoding
    return data
  if format in ('pem2', 'pkcs8', 'pkcs8pem'):
    # PKCS #8: https://en.wikipedia.org/wiki/PKCS_8
    # PEM: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
    # Chapter 10: https://tools.ietf.org/html/rfc7468#section-10
    return _bbe.join((bb('-----BEGIN PRIVATE KEY-----\n'), base64_encode(data), bb('\n-----END PRIVATE KEY-----\n')))


# --- main()


def quick_test():
  import sys
  # Example 4096-bit key (modulus size).
  d = convert_rsa_data(bb('''
      public_exponent = 0x10001
      p = 0xf0710459cd01a206f4c4dbb8cd591c3f240c887c11bfef21d00cb0b973e4adafb373c1fec279252771e78f0cde980723f97c5457e72648e2eafaea98414eb8448be103e0e276c0a772735e9eacb45e2ac8d03562ea2c72fb1b83c101e6355aae764dff1fcd7f18ea3c8c384052e64cff91a23085d1149d9ed6c7e3bfa1e09735d6ebfeb981ed168c4942f384570c54b07c01e61afc9277a959147715ec17a29fc0a41e4c694813f755ba4f5ba21f221c0ac7d44e499e0856c66c1330b4d32f09e7b4f3bb47f6a564d381872e0d2b1b3c3dc132d31500e7fa7bde2c302a217bedba964d2dbc02d84b47cbe8bafac184963e65b028d9f6fa71b975440d0513aea3
      q = 0xd4d51ee89043051536d581b984820ba0925c006b327490ac010b27780b4612873d7c1ed1accd4e994518a51252de889410c8fefdb7fbfe05352506897a8e507eda7063ff33adda4020be19a32b26d13f35c0aa92d67cdca855561feb0e8d929481e29ce65906acc37eb514ac9b4743d8b6605ff6caa4abb1372c5b6d3c15639fc441cf5780f5dce59dc71c04e41b396bb84162b6d26f33b83ab6f63635f637d0dc36d263ba78c1bd0ba80726cda6ec09e90cd4933948ec17d43762f54c3fa8d33ed90b62204f35ba8b9354addbf227437ff5fe7f6602a3377f48a5e4db2fadd97b02ffe394a9cf2ffef2bbb1c0fa7b495306a4191aa9f4c5fea6dc9ec5c41263
  '''), 'dict')
  assert is_rsa_private_key_complete(d)
  open('t.der', 'wb').write(convert_rsa_data(d, 'der'))
  open('t.pem', 'wb').write(convert_rsa_data(d, 'pem'))
  open('t2.der', 'wb').write(convert_rsa_data(d, 'der2'))
  open('t2.pem', 'wb').write(convert_rsa_data(d, 'pem2'))
  open('t.dropbear', 'wb').write(convert_rsa_data(d, 'dropbear'))
  open('t.openssh', 'wb').write(convert_rsa_data(d, 'openssh'))
  open('t.opensshsingle', 'wb').write(convert_rsa_data(d, 'opensshsingle'))
  open('t.opensshld', 'wb').write(convert_rsa_data(d, 'opensshld'))
  open('t.opensshbin', 'wb').write(convert_rsa_data(d, 'opensshbin'))
  open('t.msblob', 'wb').write(convert_rsa_data(d, 'msblob'))
  open('t.hexa', 'wb').write(convert_rsa_data(d, 'hexa'))
  open('t.gpg22', 'wb').write(convert_rsa_data(d, 'gpg22'))
  open('t.gpg23', 'wb').write(convert_rsa_data(d, 'gpg23'))

  public_exponent, private_exponent, prime1, prime2, exponent1, exponent2, coefficient, modulus = (
      d['public_exponent'], d['private_exponent'], d['prime1'], d['prime2'], d['exponent1'], d['exponent2'], d['coefficient'], d['modulus'])
  # All 256, i.e. about 2048 bits.
  assert (len('%x' % prime1) >> 1) == 256
  assert (len('%x' % prime2) >> 1) == 256
  assert (len('%x' % exponent1) >> 1) == 256
  assert (len('%x' % exponent2) >> 1) == 256
  assert (len('%x' % coefficient) >> 1) == 256
  print('OK0')
  sys.stdout.flush()

  gcdm = gcd(prime1 - 1, prime2 - 1)
  lcm = (prime1 - 1) * (prime2 - 1) // gcdm
  assert gcd(public_exponent, lcm) == 1
  # Equivalent to private_exponent2 for pow(msg, ..., modulus) purposes.
  private_exponent2 = private_exponent % lcm
  assert 1 <= private_exponent2 < lcm
  assert gcd(private_exponent, lcm) == 1
  #print(gcd(prime1 - 1, prime2 - 1))  # Can be larger than 1.
  assert private_exponent2 == crt2(exponent1, prime1 - 1, exponent2, (prime2 - 1) // gcdm)
  assert private_exponent2 == crt2(exponent1, (prime1 - 1) // gcdm, exponent2, (prime2 - 1))
  print('OK1')
  sys.stdout.flush()

  # Takes a few (10) seconds, depends on random.
  #assert prime1 == recover_rsa_prime1_from_exponents(modulus, private_exponent, public_exponent)

  print('OK2')
  sys.stdout.flush()
  x = 41
  y = pow(x, private_exponent, modulus)
  mp1 = pow(x, exponent1, prime1)
  mp2 = pow(x, exponent2, prime2)
  y2 = pow(x, private_exponent2, modulus)
  y3 = crt2(mp1, prime1, mp2, prime2)
  y4 = (mp2 + prime2 * coefficient * (mp1 - mp2)) % modulus  # Fastest to compute, because mp1 and mp2 modular exponentiation have small (half-size) modulus.
  assert y == y4
  assert y == y2
  assert y == y3  # True for all x < modulus, even for non-relative-primes.
  assert pow(y, public_exponent, modulus) == x  # True for all x < modulus, even for non-relative-primes.

  print('OK')
  sys.stdout.flush()


def check_gpg_userid(comment):
  if not comment:
    sys.stderr.write('fatal: specify user ID as -comment ... for -outform gpg\n')
    sys.exit(2)
  if not is_gpg_userid(comment):
    sys.stderr.write('info: example good GPG user ID: -comment "Test Real Name 6 (Comment 6) <testemail6@email.com>"\n')
    sys.stderr.write('fatal: bad GPG user ID: %s\n' % repr(comment).lstrip(bb('b')))
    sys.exit(2)


def ensure_creation_time(d):
  if 'creation_time' not in d:
    import time
    d['creation_time'] = int(time.time())


def parse_bitsize(arg):
  try:
    return int(arg)
  except ValueError:
    pass
  sys.stderr.write('fatal: bad <bitsize>: %s\n' % argv[i])
  sys.exit(1)


def update_format(old_format, format):
  if format in ('der', 'pem') and old_format in ('der2', 'pem2', 'pcks8der', 'pcks8pem', 'pcks8'):
    # Make `rsakeytool.py genpkey -outform pem' use format='pkcs8pem'.
    return 'pkcs8' + format
  else:
    return format


def is_ascii_format(format):
  return format in ('openssh', 'sshpublic', 'gpgascii', 'gpgpublicascii', 'gpg23', 'gpglist', 'pem2', 'dict', 'hexa', 'pkcs1pempublic', 'pkcs8pempublic') or format.endswith('pem')


def get_public_format(format):
  if format.endswith('public'):
    return format
  if format == 'pem':
    return 'pkcs8pempublic'  # Compatible with OpenSSL 1.1.0l.
  if format == 'der':
    return 'pkcs8derpublic'  # Compatible with OpenSSL 1.1.0l.
  if format.startswith('openssh') or format == 'dropbear':
    return 'sshpublic'
  if format == 'gpg':
    return 'gpgpublic'
  if format in ('pkcs1der',):
    return 'pkcs1derpublic'
  if format in ('pkcs1', 'pkcs1pem'):
    return 'pkcs1pempublic'
  if format in ('der2', 'pkcs8der'):
    return 'pkcs8derpublic'
  if format in ('pem2', 'pkcs8', 'pkcs8pem'):
    return 'pkcs8pempublic'
  return None


def write_to_file(outfn, data):
  if outfn is None:
    sys.stdout.write(aa_strict(data))
    sys.stdout.flush()
  else:
    f = open(outfn, 'wb')
    try:
      f.write(data)
    finally:
      f.close()


def main_generate(argv):
  i = 1
  is_close_odd = False
  format = bitsize = outfn = comment = algorithm = None
  while i < len(argv):
    arg = argv[i]
    i += 1
    if arg == '-dump':
      outfn, format = None, 'hexa'
      continue
    if arg == '-closeodd':
      is_close_odd = True
      continue
    if arg not in ('-out', '-outform', '-comment', '-algorithm', '-pkeyopt'):  # openssl(1) doesn't have `-outform' here.
      if arg.startswith('-'):
        sys.stderr.write('fatal: unknown flag (use --help): %s\n' % arg)
        sys.exit(1)
      i -= 1
      break
    if i == len(argv):
      sys.stderr.write('fatal: missing argument for flag: %s\n' % arg)
      sys.exit(1)
    value = argv[i]
    i += 1
    if arg == '-out':
      outfn = value
    elif arg == '-comment':
      comment = value
    elif arg == '-algorithm':
      value1 = value.lower()
      if value1 != 'rsa':
        sys.stderr.write('fatal: unknown algorithm: -algorithm %s\n' % value)
        sys.exit(1)
      algorithm = value1
    elif arg == '-pkeyopt':
      if ':' not in value:
        sys.stderr.write('fatal: missing value: -pkeyopt %s\n' % value)
        sys.exit(1)
      key, value = value.split(':', 1)
      key1 = key.lower()
      if key1 != 'rsa_keygen_bits':
        sys.stderr.write('fatal: unknown key option: -pkeyopt %s:...\n' % key)
        sys.exit(1)
      bitsize = parse_bitsize(value)
    elif arg == '-outform':
      format = update_format(format, value.lower())
  if bitsize is None:
    if i == len(argv):
      sys.stderr.write('fatal: missing <bitsize>\n')
      sys.exit(1)
    bitsize = parse_bitsize(argv[i])
    i += 1
  if i != len(argv):
    sys.stderr.write('fatal: too many command-line arguments\n')
    sys.exit(1)
  if format is None:
    sys.stderr.write('fatal: missing -outform ...\n')
    sys.exit(1)
  if algorithm is None:
    sys.stderr.write('fatal: missing -algorithm rsa.\n')
    sys.exit(1)
  if outfn is None and not is_ascii_format(format):
    sys.stderr.write('fatal: missing -out ... for non-ASCII -outform %s\n' % format)
    sys.exit(1)
  if comment is not None:
    # TODO(pts): Allow non-ASCII comment bytes (e.g. UTF-8 or locale default)?
    comment = bb(comment)
  if format in ('gpg', 'gpgpublic'):
    if bitsize < 489:
      # This assumes hash_name='sha256'.
      sys.stderr.write('fatal: genrsa conflicts with -outform gpg and <bitsize> too small for hash output: %d\n' % bitsize)
      sys.exit(1)
    if is_bitsize_of_single_rsa_key(bitsize):
      sys.stderr.write('fatal: genrsa conflicts with -outform gpg and small <bitsize>: %d\n' % bitsize)
      sys.exit(1)
    check_gpg_userid(comment)

  # This is much slower than `openssl genrsa ...', mostly because of the
  # pow(a, n2, n) call. For bitsize == 4096, this may take up to 30 seconds,
  # while `openssl genrsa ...' takes less than 6 seconds.
  d = generate_rsa(bitsize, is_close_odd=is_close_odd)
  d0 = get_rsa_private_key(**d)
  assert d0 == d, 'Bad RSA private key generated.'
  if comment is not None:
    d['comment'] = comment
  if format in ('gpg', 'gpgpublic'):
    check_gpg_userid(d.get('comment'))
    ensure_creation_time(d)
    d_sub = generate_rsa(bitsize)
    while d_sub == d0:
      d_sub = generate_rsa(bitsize)
    assert get_rsa_private_key(**d_sub) == d_sub, 'Bad RSA private key generated.'
    d_sub['creation_time'] = d['creation_time']
    d['sub'] = d_sub
    del d_sub

  data = convert_rsa_data(d, format)
  if format == 'dict':
    data = portable_repr(data, suffix=bbnl)
  write_to_file(outfn, data)


def main(argv):
  import sys
  if len(argv) > 1 and argv[1] == '--quick-test':
    quick_test()
    return
  if len(argv) < 2 or argv[1] in ('--help', '-help') or (len(argv) > 2 and not argv[1].startswith('-') and argv[2] in ('--help', '-help')):
    sys.stderr.write(
        'rsakeytool.py: Convert between various RSA private key formats.\n'
        'This is free software, GNU GPL >=2.0. '
        'There is NO WARRANTY. Use at your risk.\n'
        'Usage: %s rsa [<flag> ...]\n'
        'Flags for rsa:\n'
        '-dump: Print the RSA private key as hex number assignments to stdout.\n'
        '-in <input-filename>: Read RSA private key from this file.\n'
        '-out <output-filename>: Write RSA private key to this file, in output format -outform ...\n'
        '-pubout: Write public key only in format corresponding to -outform ...\n'
        '-outform <output-format>: Any of pem == pkcs1pem (default), pkcs8pem, pcks1der, pkcs8der, '
        'msblob, dropbear, openssh (also opensshsingle, opensshld, opensshbin), sshpublic (output only), '
        'pkcs1derpublic (output only), pkcs1pempublic (output only), pkcs8derpublic (output only), pkcs8pempublic (output only), '
        'hexa, dict (output only), gpg (output only), gpgpublic (output only), gpg22, gpg23.\n'
        '-inform <input-format>: Ignored. Autodetected instead.\n'
        '-keyid <key-id>: Selects GPG key to read from file. Omit to get a list.\n'
        '-subin <subkey-input-filename>: Read GPG encryption subkey from this file for -outform gpg\n'
        '-comment <comment>: For the specified comment in the output file. Makes a difference for -outform hexa|openssh|gpg\n'
        'Usage: %s {genrsa|genpkey} [<flag> ...] [<bitsize>]\n'
        'Flags for genrsa and genpkey:\n'
        '-out <output-filename>: Write RSA private key to this file, in output format -outform ...\n'
        '-outform <output-format>: Any of pem == pkcs1pem (default) and others (see above).\n'
        '-comment <comment>: For the specified comment in the output file. Makes a difference for -outform hexa|openssh|gpg\n'
        '-pkeyopt rsa_keygen_bits:<bitsize>: Another way to specify <bitsize> for genpkey.\n'
        '-closeodd: Make primes have the same bitsize for odd <bitsize>.\n'
        'See details on https://github.com/pts/pyrsakeytool\n'
        .replace('%s', argv[0]))
    sys.exit(1)
  if argv[1] == 'genrsa':  # openssl genrsa -out key.pem 4096
    argv = list(argv)
    argv[1 : 2] = ('-outform', 'pkcs1pem', '-algorithm', 'rsa')
    return main_generate(argv)
  elif argv[1] == 'genpkey':  # openssl genpkey -algorithm rsa -out key.pem -pkeyopt rsa_keygen_bits:4096
    argv = list(argv)
    argv[1 : 2] = ('-outform', 'pkcs8pem')
    return main_generate(argv)
  i = 1
  if argv[1] == 'rsa':  # Compatible with `openssl rsa ...'.
    #sys.stderr.write('fatal: specify rsa as first argument\n')
    #sys.exit(1)
    i += 1

  keyid = infn = outfn = subinfn = comment = None
  is_public = False
  format = 'pem'
  while i < len(argv):
    arg = argv[i]
    i += 1
    if arg == '-dump':
      outfn, format = None, 'hexa'
      continue
    elif arg == '-pubout':
      is_public = True
      continue
    if arg not in ('-in', '-subin', '-out', '-outform', '-inform', '-keyid', '-comment'):
      sys.stderr.write('fatal: unknown flag (use --help): %s\n' % arg)
      sys.exit(1)
    if i == len(argv):
      sys.stderr.write('fatal: missing argument for flag: %s\n' % arg)
      sys.exit(1)
    value = argv[i]
    i += 1
    if arg == '-in':
      infn = value
    elif arg == '-subin':
      subinfn = value
    elif arg == '-out':
      outfn = value
    elif arg == '-keyid':
      keyid = value.upper()
    elif arg == '-comment':
      comment = value
    elif arg == '-outform':
      format = update_format(format, value.lower())
    # FYI `-inform ...' is silently ignored, because rsakeytool.py
    # autodetects the input file format.
  if infn is None:
    sys.stderr.write('fatal: missing -in ...\n')
    sys.exit(1)
  if format is None:
    sys.stderr.write('fatal: missing -outform ...\n')
    sys.exit(1)
  if is_public:
    format2 = get_public_format(format)
    if format2 is None:
      sys.stderr.write('fatal: no public key format for -outform %s\n' % format)
      sys.exit(1)
    format = format2
  if outfn is None and not is_ascii_format(format):
    sys.stderr.write('fatal: missing -out ... for non-ASCII -outform %s\n' % format)
    sys.exit(1)
  if subinfn is not None and format not in ('gpg', 'gpgpublic'):
    sys.stderr.write('fatal: -subin needs -outform gpg or -outform gpgpublic\n')
    sys.exit(1)

  f = open(infn, 'rb')
  try:
    data = f.read()  # TODO(pts): Limit to 1 MiB etc., but not for gpg(1).
  finally:
    f.close()
  if comment is not None:
    data = convert_rsa_data(data, 'dict', effort=0)
    # TODO(pts): Allow non-ASCII comment bytes (e.g. UTF-8 or locale default)?
    data['comment'] = bb(comment)
  if format in ('gpg', 'gpgpublic'):
    data = convert_rsa_data(data, 'dict', effort=0)
    check_gpg_userid(data['comment'])
    ensure_creation_time(data)
  if subinfn is None:
    if format in ('gpg', 'gpgpublic'):
      sys.stderr.write('warning: encryption subkey (-subin ...) is strongly recommended for -outform gpg\n')
  else:
    f = open(subinfn, 'rb')
    try:
      subdata = f.read()
    finally:
      f.close()
    data = convert_rsa_data(data, 'dict', effort=0)
    data['sub'] = convert_rsa_data(subdata, 'dict')
    data['sub'].setdefault('creation_time', data['creation_time'])
    del subdata  # Save memory.

  data = convert_rsa_data(data, format, keyid=keyid)
  if format == 'dict':
    data = portable_repr(data, suffix=bbnl)
  write_to_file(outfn, data)


if __name__ == '__main__':
  import sys
  sys.exit(main(sys.argv))

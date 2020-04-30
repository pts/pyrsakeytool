#! /bin/sh
# by pts@fazekas.hu at Sat Apr 25 01:21:50 CEST 2020
#

""":" # rsakeytool.py: Convert between various RSA private key formats.

type python    >/dev/null 2>&1 && exec python    -- "$0" ${1+"$@"}
type python3   >/dev/null 2>&1 && exec python3   -- "$0" ${1+"$@"}
type python2.7 >/dev/null 2>&1 && exec python2.7 -- "$0" ${1+"$@"}
type python2.6 >/dev/null 2>&1 && exec python2.6 -- "$0" ${1+"$@"}
type python2.5 >/dev/null 2>&1 && exec python2.5 -- "$0" ${1+"$@"}
type python2.4 >/dev/null 2>&1 && exec python2.4 -- "$0" ${1+"$@"}
exec python -- ${1+"$@"}; exit 1  # Just for the error message.

This script needs Python 2.4, 2.5, 2.6, 2.7 or 3.x.
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
else:  # Python 3.x.
  def bb(data):
    return bytes(data, 'ascii')
  def aa(data):
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


def uint_to_any_be(value, is_low=False, is_hex=False,
                    _bbz=bbz, _bb0=bb('0'), _bb8=bb('8'), _bb00=bb('00'), _bbpx=bb('%x')):
  if value < 0:
    raise ValueError('Bad negative uint.')
  if not (is_low or is_hex) and value <= 0xffffffffffffffff:
    return struct.pack('>Q', value).lstrip(_bbz) or _bbz
  else:
    try:
      value = _bbpx % value
    except TypeError:  # Python 3.0--3.4.
      # In Python 2, we'd have to do hex(value).rstrip('L').
      value = bytes(hex(value), 'ascii')[2:]
    if len(value) & 1:
      value = _bb0 + value
    elif is_low and not _bb0 <= value[:1] < _bb8:
      value = _bb00 + value
    if is_hex:
      return value
    return binascii.unhexlify(value)


if getattr(int, 'from_bytes', None):
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
  return uint_to_any_be(value, True, is_hex=True).upper()


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
  coefficient = None  # Ignore until recalculated below.
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
  if 'checkint' in kwargs and not isinstance(kwargs['checkint'], integer_types) and kwargs['checkint'] >> 32:
    raise ValueError('Bad checkint: %r' % (kwargs['checkint'],))
  for key in ('comment', 'checkint'):
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


# --- Hashes.


try:
  new_sha1 = __import__('hashlib').sha1  # Python 2.5--.
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


  def slow_sha256_process(block, hh, _izip=__import__('itertools').izip, _rotr32=_sha256_rotr32, _k=_sha256_k):
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
        hh, i, _buffer = self._h, 0, buffer
        if lb:
          assert lb < 64
          i = 64 - lb
          hh = process(buf + bytes(m[:i]), hh)
        for i in xrange(i, lm - 63, 64):
          hh = process(_buffer(m, i, 64), hh)
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
    raise Value('n is too short.')
  # Same but slower: return -1 & ((1 << ((n_size << 3) - 15)) - (1 << ((t_size + 1) << 3))) | t
  return (1 << ((n_size << 3) - 15)) - ((1 << ((t_size + 1) << 3)) - t)


# (hash_name, hash_algo, hash_size, asn1_header).
# https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.2.2
# TODO(pts): Add md5 and sha*.
GPG_HASH_INFOS = {
    'sha1': ('sha1', 2, 20, binascii.unhexlify('3021300906052b0e03021a05000414'), new_sha1),
    # 3031: sequence of 49 bytes
    #   300D: sequence of 13 bytes
    #     0609: oid of 9 bytes
    #       608648016503040201: OID of SHA-256
    #     0500: None
    #   0420: uint of 32 bytes
    #     ????????????????????????????????????????????????????????????????: sha256_hexdigest
    'sha256': ('sha256', 8, 32, binascii.unhexlify('3031300d060960864801650304020105000420'), new_sha256),
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


OCTDIGIT_BITCOUNT = {bb('0'): 1, bb('1'): 1, bb('2'): 2, bb('3'): 2, bb('4'): 3, bb('5'): 3, bb('6'): 3, bb('7'): 3}


def append_gpg_mpi(output, value, _bb0=bb('0'), _bb8=bb('8'), _bb00=bb('00'), _bbpx=bb('%x')):
  """Returns a GPG MPI representation of uint value."""
  if not isinstance(value, integer_types):
    raise ValueError
  if value < 0:
    raise TypeError('Negative GPG MPI.')
  try:
    value = _bbpx % value
  except TypeError:  # Python 3.0--3.4.
    value = bytes(hex(value), 'ascii')[2:]
  if len(value) & 1:
    value = _bb0 + value
  bitsize = -8
  if value.startswith(_bb0):
    c, bitsize = value[1 : 2], -8
  else:
    c, bitsize = value[:1], -4
  bitsize += OCTDIGIT_BITCOUNT.get(c, 4)
  data = binascii.unhexlify(value)
  bitsize += len(data) << 3
  if bitsize >> 16:
    raise TypeError('GPG MPI too long.')
  output.append(struct.pack('>H', bitsize))
  output.append(data)


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


def build_gpg_export_secret_key_data(d, d_sub, hash_name='sha256', _bbe=bbe):
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
    return _bbe.join((
        build_gpg_packet_header(5, len(private_key_packet_data)), private_key_packet_data,
        build_gpg_packet_header(13, len(d['comment'])), d['comment'],
        build_gpg_packet_header(2, len(userid_cert_signature_packet_data)), userid_cert_signature_packet_data,
    ))
  else:
    raise TypeError('Bad subkey type: %r' % type(d_sub))
  userid_cert_signature_packet_data = build_gpg_userid_cert_rsa_signature_packet_data(d, hash_name, public_key_packet_data, key_id20)
  public_subkey_packet_data = private_subkey_packet_data[:get_gpg_public_key_packet_size(private_subkey_packet_data)]
  subkey_signature_packet_data = build_gpg_subkey_rsa_signature_packet_data(d, public_subkey_packet_data, hash_name, public_key_packet_data, key_id20)
  return _bbe.join((
      build_gpg_packet_header(5, len(private_key_packet_data)), private_key_packet_data,
      build_gpg_packet_header(13, len(d['comment'])), d['comment'],
      build_gpg_packet_header(2, len(userid_cert_signature_packet_data)), userid_cert_signature_packet_data,
      build_gpg_packet_header(7, len(private_subkey_packet_data)), private_subkey_packet_data,
      build_gpg_packet_header(2, len(subkey_signature_packet_data)), subkey_signature_packet_data,
  ))


# --- Serialization and parsing.


def serialize_rsa_der(d):
  # DER and PEM generators (ASN.1): https://0day.work/how-i-recovered-your-private-key-or-why-small-keys-are-bad/
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


HEXA_KEYS = ('modulus', 'public_exponent', 'private_exponent', 'prime1', 'prime2', 'exponent1', 'exponent2', 'coefficient', 'comment', 'checkint')
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


BYTES_UNESCAPES = {bb('a'): bb('\a'), bb('b'): bb('\b'), bb('f'): bb('\f'), bb('n'): bb('\n'), bb('r'): bb('\r'), bb('t'): bb('\t'), bb('v'): bb('\v')}


def parse_repr_bytes(data, _bbqs=(bb('b\''), bb('b"')), _bbnl=bbnl, _bbbs=bb('\\'), _bbe=bbe, _bbxx=bb('xX'), _bb0123=bb('0123'),
                     _bbbsbs=bb('\\\\'), _bbr1=bb('\\x5c'), _bbr2=bb('\\\''), _bbr3=bb('\\x27'), _bbr4=bb('\\"'), _bbr5=bb('\\x22')):
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
        c = BYTES_UNESCAPES.get(c)
        if not c:
          raise ValueError('Bad backslash escape: %r' % data[i : i + 1])
        i += 2
      output.append(c)
    data = _bbe.join(output)
  return data


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


def serialize_rsa_hexa(d, _bbassign=bb(' = '), _bb0x=bb('0x'), _bbnl=bbnl, _bbe=bbe, _bbpx=bb('%x'), _bb0=bb('0')):
  """Serializes hexa: hexadecimal assignment."""
  output = []
  for key in HEXA_KEYS:
    if key not in d:
      if key not in ('comment', 'checkint'):
        raise KeyError('RSA key missing: %r' % key)
      continue
    value = d[key]
    output.append(bb(key))
    output.append(_bbassign)
    if key == 'comment':
      value = repr(value)
      if value[:1] in '"\'':
        value = 'b' + value  # Binary string in Python 2.x.
      output.append(bb(value))
    else:
      try:
        value = _bbpx % value
      except TypeError:  # Python 3.0--3.4.
        value = bytes(hex(value), 'ascii')
        if len(value) & 1:
          output.append(_bb0x)
          output.append(_bb0)
          value = value[2:]
        output.append(value)
        value = ()
      if value:
        output.append(_bb0x)
        if len(value) & 1:
          output.append(_bb0)
        output.append(value)
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
                     _bb00=bb('\0\0')):
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
    if format in 'gpg22':
      return serialize_rsa_gpg22(d)
    if format in 'gpg23':
      return serialize_rsa_gpg23(d)
    if format not in ('der', 'pem', 'der2', 'pem2'):
      raise ValueError('Unknown RSA private key format: %r' % (format,))
    d, data = None, serialize_rsa_der(d)
  if not (isinstance(data, bytes) and d is None):
    raise TypeError
  if format == 'der':
    return data
  if format == 'pem':
    return _bbe.join((bb('-----BEGIN RSA PRIVATE KEY-----\n'), base64_encode(data), bb('\n-----END RSA PRIVATE KEY-----\n')))
  data = der_value((0, (DER_OID_RSA_ENCRYPTION, None), der_bytes(data)))
  if format == 'der2':
    return data
  if format == 'pem2':
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


def main(argv):
  import sys
  if len(argv) > 1 and argv[1] == '--quick-test':
    quick_test()
    return
  if len(argv) < 2 or argv[1] in ('--help', '-help') or (len(argv) > 2 and argv[1] == 'rsa' and argv[2] in ('--help', '-help')):
    sys.stderr.write(
        'rsakeytool.py: Convert between various RSA private key formats.\n'
        'This is free software, GNU GPL >=2.0. '
        'There is NO WARRANTY. Use at your risk.\n'
        'Usage: %s rsa [<flag> ...]\n'
        'Flags:\n'
        '-dump\n'
        '-in <input-filename>\n'
        '-out <output-filename>\n'
        '-outform <output-format>: Any of der, pem (default), der2, pem2, msblob, dropbear, openssh (also opensshsingle, opensshld, opensshbin), hexa, gpg22, gpg23.\n'
        '-inform <input-format>: Ignored. Autodetected instead.\n'
        '-keyid <key-id>: Selects GPG key to load from file. Omit to get a list.\n'
        .replace('%s', argv[0]))
    sys.exit(1)
  i = 1
  if argv[1] == 'rsa':  # Compatible with `openssl rsa ...'.
    #sys.stderr.write('fatal: specify rsa as first argument\n')
    #sys.exit(1)
    i += 1

  keyid = infn = outfn = None
  format = 'pem'
  while i < len(argv):
    arg = argv[i]
    i += 1
    if arg == '-dump':
      format = 'dict'
      continue
    if arg not in ('-in', '-out', '-outform', '-inform', '-keyid'):
      sys.stderr.write('fatal: unknown flag (use --help): %s\n' % arg)
      sys.exit(1)
    if i == len(argv):
      sys.stderr.write('fatal: missing argument for flag: %s\n' % arg)
      sys.exit(1)
    value = argv[i]
    i += 1
    if arg == '-in':
      infn = value
    elif arg == '-out':
      outfn = value
    elif arg == '-keyid':
      keyid = value.upper()
    elif arg == '-outform':
      if value == 'dict':
        sys.stderr.write('fatal: -outform dict not supported on the command-line\n')
        sys.exit(1)
      format = value.lower()
    # FYI `-inform ...' is silently ignored, because rsakeytool.py
    # autodetects the input file format.
  if infn is None:
    sys.stderr.write('fatal: missing -in ...\n')
    sys.exit(1)
  if format is None:
    sys.stderr.write('fatal: missing -outform ...\n')
    sys.exit(1)
  if outfn is None and format != 'dict':
    sys.stderr.write('fatal: missing -out ...\n')
    sys.exit(1)
  if outfn is not None and format == 'dict':
    sys.stderr.write('fatal: unexpected -out ... for -dump\n')
    sys.exit(1)

  f = open(infn, 'rb')
  try:
    data = f.read()  # TODO(pts): Limit to 1 MiB etc., but not for gpg(1).
  finally:
    f.close()
  if format == 'dict':  # -dump.
    sys.stdout.write(aa(convert_rsa_data(data, 'hexa', keyid=keyid)))
    sys.stdout.flush()
  else:
    data = convert_rsa_data(data, format)
    f = open(outfn, 'wb')
    try:
      f.write(data)
    finally:
      f.close()


if __name__ == '__main__':
  import sys
  sys.exit(main(sys.argv))

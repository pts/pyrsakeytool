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

# --- ASN.1 DER and PEM.

try:
  long
  integer_types = (int, long)
except NameError:
  integer_types = (int,)


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


def uint_to_any_be(value, is_low=False,
                    _bbz=bbz, _bb0=bb('0'), _bb8=bb('8'), _bb00=bb('00'), _bbpx=bb('%x')):
  if value < 0:
    raise ValueError('Bad negative uint.')
  if not is_low and value <= 0xffffffffffffffff:
    return struct.pack('>Q', value).lstrip(_bbz) or _bbz
  else:
    try:
      value = _bbpx % value
    except TypeError:  # Python 3.1.
      value = bytes(hex(value), 'ascii')[2:]
    if len(value) & 1:
      value = _bb0 + value
    elif is_low and not _bb0 <= value[:1] < _bb8:
      value = _bb00 + value
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


def base64_encode(data, _bbnl=bbnl):
  data = binascii.b2a_base64(data).rstrip(_bbnl)
  if not isinstance(data, bytes):
    raise TypeError
  output, i = [], 0
  while i < len(data):
    output.append(data[i : i + 64])  # base64.encodestring uses 76.
    i += 64
  return _bbnl.join(output)


# --- Dropbear SSH private key format.


def parse_dropbear_uint(data, i, j=None):
  if j is not None and j < i + 4:
    raise ValueError('EOF in size-limited dropbear uint size.')
  if len(data) < i + 4:
    raise ValueError('EOF in dropbear uint size.')
  size, = struct.unpack('>L', data[i : i + 4])
  i += 4
  if j is not None and j < i + size:
    raise ValueError('EOF in size-limited dropbear uint.')
  if len(data) < i + size:
    raise ValueError('EOF in dropbear uint.')
  if size > 0 and struct.unpack('>B', data[i : i + 1])[0] >= 0x80:
    raise ValueError('Negative dropbox uint.')
  return i + size, uint_from_be(data[i : i + size])


def dropbear_value(value):
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
    raise ValueError('Bad modulus.')
  try:
    coefficient = modinv(prime2, prime1)
  except ValueError:
    coefficient = None
  if coefficient is None:
    raise ValueError('Primes are not coprimes.')
  pp1 = (prime1 - 1) * (prime2 - 1)
  if ec < 1:
    raise ValueError('Needed at least 1 of private_exponent, public_exponent.')
  if not 0 <= private_exponent < pp1:
    raise ValueError('Bad private_exponent.')
  if not 0 <= public_exponent < pp1:
    raise ValueError('Bad public_exponent.')
  if not private_exponent:
    private_exponent = modinv(public_exponent, pp1)
  elif not public_exponent:
    public_exponent = modinv(private_exponent, pp1)
  elif private_exponent * public_exponent % pp1 != 1:
    raise ValueError('Mismatch in private_exponent vs public_exponent.')
  lcm = pp1 // gcd(prime1 - 1, prime2 - 1)
  if gcd(public_exponent, lcm) != 1:
    raise ValueError('Mismatch in public_exponent vs primes.')
  if gcd(private_exponent, lcm) != 1:
    raise ValueError('Mismatch in private_exponent vs primes.')
  # OpenPGP RSA private key:
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.6
  # * modulus: (public) MPI of RSA public modulus n;
  # * public_exponent: (public) MPI of RSA public encryption exponent e, usually 0x10001.
  # * private_exponent: MPI of RSA secret exponent d;
  # * prime2: (smaller prime) MPI of RSA secret prime value p;
  # * prime1: (larger prime) MPI of RSA secret prime value q (p < q);
  # * coefficient: MPI of u, the multiplicative inverse of p, mod q.
  return {
      'modulus': modulus,  # Public.
      'prime1': prime1,
      'prime2': prime2,
      'public_exponent': public_exponent,  # Public.
      'private_exponent': private_exponent,
      'exponent1': private_exponent % (prime1 - 1),
      'exponent2': private_exponent % (prime2 - 1),
      'coefficient': coefficient,
  }


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
          d['private_exponent'] * d['public_exponent'] % pp1 == 1 and
          d['exponent1'] == d['private_exponent'] % pm1,
          d['exponent2'] == d['private_exponent'] % pm2):
        return False
      if effort >= 4:
        lcm = pp1 // gcd(pm1, pm2)
        if not (gcd(d['public_exponent'], lcm) == 1 and
                gcd(d['private_exponent'], lcm) == 1):
          return False
        # With `if effort >= 5' we could check that prime1 and prime2 are
        # primes.
  return True


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
    raise ValueError('Expected der or pem input.')
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
                  _bbe=bbe, _bbd=bb('-'),
                  _bb30=bb('\x30'), _bb50=bb('\5\0'), _bbbegin=bb('\n-----BEGIN '), _bbend=bb('\n-----END '), _bbnl=bbnl, _bbcolon=bb(':'),
                  _bbencrypted=bb('ENCRYPTED '), _bbrsapk=bb('RSA PRIVATE KEY-----\n'), _bbpk=bb('PRIVATE KEY-----\n')):
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
  if data[i : i + len(_bbrsapk)] == _bbrsapk:
    pass
  elif data[i : i + len(_bbpk)] == _bbpk:
    pass
  elif data[i : i + len(_bbencrypted)] == _bbencrypted:
    raise ValueError('Encrypted pem not supported.')
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
    raise ValueError('Encrypted RSA private key not supported.')
  # TODO(pts): Check for disallowed characters (e.g. ~) in data.
  return binascii.a2b_base64(data)


def parse_rsa_dropbear_numbers(data, i=0, j=None):
  if j is None:
    j = len(data)
  d = {}
  i, d['public_exponent'] = parse_dropbear_uint(data, i, j)
  i, d['modulus'] = parse_dropbear_uint(data, i, j)
  i, d['private_exponent'] = parse_dropbear_uint(data, i, j)
  i, d['prime1'] = parse_dropbear_uint(data, i, j)
  # prime2 is the last number in the file, but we don't need it.
  # i, d['prime2'] = parse_dropbear_uint(data, i, j)
  return d


bbsshrsa = bb('\0\0\0\7ssh-rsa')  # TODO(pts): Uppercase variable names.


def serialize_rsa_dropbear(d, _bbe=bbe, _bbsshrsa=bbsshrsa):
  return _bbe.join((_bbsshrsa, dropbear_value(d['public_exponent']), dropbear_value(d['modulus']), dropbear_value(d['private_exponent']), dropbear_value(d['prime1']), dropbear_value(d['prime2'])))


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


HEXA_KEYS = ('modulus', 'public_exponent', 'private_exponent', 'prime1', 'prime2', 'exponent1', 'exponent2', 'coefficient')
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
    key = HEXA_ALIASES.get(key, key)
    if key not in HEXA_KEYS:
      raise ValueError('Unknown assignment key: %r' % key)
    if key in d:
      raise ValueError('Duplicate assignment key %r.' % key)
    while data[i : i + 1].isspace():
      i += 1
    i2 = i
    while j > i and not data[i : i + 1].isspace():
      i += 1
    try:
      value = int(data[i2 : i], 0)
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


def serialize_rsa_hexa(d, _bbassign=bb(' = '), _bb0x=bb('0x'), _bbnl=bbnl, _bbe=bbe, _bbpx=bb('%x')):
  """Serializes hexa: hexadecimal assignment."""
  output = []
  for key in HEXA_KEYS:
    value = d[key]
    output.append(bb(key))
    output.append(_bbassign)
    try:
      value = _bbpx % value
    except TypeError:  # Python 3.1.
      output.append(bytes(hex(value), 'ascii'))
      value = ()
    if value:
      output.append(_bb0x)
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


def convert_rsa_data(d, format='pem', effort=None,
                     _bbe=bbe, _bbd=bb('-'), _bbsshrsa=bbsshrsa, _bbmsblob=bbmsblob):
  if isinstance(d, bytes):
    data = d
    if data.startswith(_bbsshrsa):
      # Dropbear SSH RSA private key format, output of:
      # dropbearconvert openssh dropbear id_rsa id_rsa.dropbear
      d = parse_rsa_dropbear_numbers(data, len(_bbsshrsa))
    elif data.startswith(_bbmsblob):
      # Microsoft SSH RSA private key format, output of:
      # openssl rsa -outform msblob -in key.pem -out key.msblob
      d = parse_rsa_msblob_numbers(data, len(_bbmsblob))
    elif has_hexa_header(data, 0):
      d = parse_rsa_hexa(data, 0)
    else:
      # TODO(pts): Add support for RSA private keys in GPG `gpg
      # --export-secret-keys', selected by key ID.
      if data.startswith(_bbd) or data[:1].isspace():  # PEM or hexa format.
        data = parse_rsa_pem(data)
      if isinstance(data, dict):
        d, data = data, None
      else:
        i, j, i0 = parse_rsa_der_header(data)  # DER format.
        if effort is None or effort >= 2 or format == 'dict':
          d = parse_rsa_der_numbers(data, i, j)
        else:
          d, data = None, data[i0 : j]
  if isinstance(d, dict):
    if not is_rsa_private_key_complete(d, effort):
      d = get_rsa_private_key(**d)
    if format == 'dict':
      return d
    if format == 'dropbear':
      return serialize_rsa_dropbear(d)
    if format == 'msblob':
      return serialize_rsa_msblob(d)
    if format == 'hexa':
      return serialize_rsa_hexa(d)
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
  raise ValueError('Unknown RSA private key format: %r' % (format,))


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
  open('t.msblob', 'wb').write(convert_rsa_data(d, 'msblob'))
  open('t.hexa', 'wb').write(convert_rsa_data(d, 'hexa'))

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
        '-outform <output-format>: Any of der, pem (default), der2, pem2, msblob, dropbear, hexa.\n'
        '-inform <input-format>; Ignored. Autodetected instead.\n'
        .replace('%s', argv[0]))
    sys.exit(1)
  i = 1
  if argv[1] == 'rsa':  # Compatible with `openssl rsa ...'.
    #sys.stderr.write('fatal: specify rsa as first argument\n')
    #sys.exit(1)
    i += 1

  infn = outfn = None
  format = 'pem'
  while i < len(argv):
    arg = argv[i]
    i += 1
    if arg == '-dump':
      format = 'dict'
      continue
    if arg not in ('-in', '-out', '-outform', '-inform'):
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
    sys.stdout.write(aa(convert_rsa_data(data, 'hexa')))
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

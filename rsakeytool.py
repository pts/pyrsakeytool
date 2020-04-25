#! /usr/bin/python
# by pts@fazekas.hu at Sat Apr 25 01:21:50 CEST 2020
#
# DER and PEM generators (ASN.1): https://0day.work/how-i-recovered-your-private-key-or-why-small-keys-are-bad/
#

import binascii
import struct

# --- ASN.1 DER and PEM.

try:
  long
except NameError:
  long = int


try:
  bytes
except NameError:
  bytes = str


def uint_to_any_msb(value, is_low=False):
  if value < 0:
    raise ValueError('Bad negative uint.')
  if not is_low and value <= 0xffffffffffffffff:
    return struct.pack('>Q', value).lstrip(b'\0') or b'\0'
  else:
    value = b'%x' % value
    if len(value) & 1:
      value = b'0' + value
    elif is_low and not b'0' <= value[:1] < b'8':
      value = b'00' + value
    return binascii.unhexlify(value)


def der_field(xtype, args):
  output = [b'', b'']
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
    output[1] = uint_to_any_msb(size)
    output[0] = struct.pack('>BB', xtype, 0x80 | len(output[1]))
  return b''.join(output)


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


assert binascii.hexlify(der_oid('1.2.840.113549.1.1.1')) == b'06092a864886f70d010101'


def der_bytes(value):
  return der_field(4, value)


def der_value(value):
  if isinstance(value, (int, long)):
    return der_field(2, uint_to_any_msb(value, is_low=True),)
  elif isinstance(value, tuple):
    return der_field(0x30, map(der_value, value))
  elif isinstance(value, bytes):
    return value
  elif value is None:
    return b'\5\0'
  else:
    raise TypeError('Bad DER data type: %s' % type(value))


def base64_encode(data):
  data = binascii.b2a_base64(data).rstrip(b'\n')
  if not isinstance(data, bytes):
    raise TypeError
  output, i = [], 0
  while i < len(data):
    output.append(data[i : i + 64])  # base64.encodestring uses 76.
    i += 64
  return b'\n'.join(output)


# --- RSA calculations.


# !! Is this faster?
#def egcd(a, b):
#    if a == 0:
#        return (b, 0, 1)
#    else:
#        g, y, x = egcd(b % a, a)
#        return (g, x - (b // a) * y, y)
#
#def modinv(a, m):
#    gcd, x, y = egcd(a, m)
#    if gcd != 1:
#        return None  # modular inverse does not exist
#    else:
#        return x % m


def modinv(a, b):
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
    x0, x1, a, b = x1 - a // b * x0, x0, b, a % b
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
    elif isinstance(value, (int, long)):
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
  elif not prime2:
    prime2 = modulus // prime1
  mc = bool(prime1) + bool(prime2) + bool(modulus)
  if mc < 3:
    raise ValueError('Found 0 in modulus, prime1, prime2.')
  if prime1 <= prime2:
    if prime1 == prime2:
      raise ValueError('Primes must not be equal.')
    prime1, prime2 = prime1, prime2
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
  if not private_exponent:
    private_exponent = modinv(public_exponent, pp1)
  elif not public_exponent:
    public_exponent = modinv(private_exponent, pp1)
  if not 1 <= private_exponent < pp1:
    raise ValueError('Bad private_exponent.')
  if not 1 <= public_exponent < pp1:
    raise ValueError('Bad private_exponent.')
  # OpenPGP RSA private key:
  # https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-09#section-5.6
  # * modulus: (public) MPI of RSA public modulus n;
  # * public_exponent: (public) MPI of RSA public encryption exponent e, usually 0x10001.
  # * private_exponent: MPI of RSA secret exponent d;
  # * prime2: (smaller prime) MPI of RSA secret prime value p;
  # * prime1: (larger prime) MPI of RSA secret prime value q (p < q);
  # * exponent: MPI of u, the multiplicative inverse of p, mod q.
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


def is_rsa_private_key_complete(d):
  if not isinstance(d, dict):
    raise TypeError
  # !! Do a more thorough check by default, like this:
  #   assert is_prime(prime1)
  #   assert is_prime(prime2)
  #   assert modulus == prime1 * prime2
  #   lcm = (prime1 - 1) * (prime2 - 1) // gcd(prime1 - 1, prime2 - 1)
  #   assert 1 <= public_exponent < lcm
  #   assert gcd(public_exponent, lcm) == 1
  #   #assert 1 <= private_exponent < lcm  # Not true in the example.
  #   assert gcd(private_exponent, lcm) == 1
  #   private_exponent = modinv(public_exponent, (prime1 - 1) * (prime2 - 1))
  #   coefficient == modinv(prime2, prime1)
  #   exponent1 == private_exponent % (prime1 - 1)
  #   exponent2 == private_exponent % (prime2 - 1)
  return bool(
      d.get('modulus') and d.get('public_exponent') and
      d.get('private_exponent') and d.get('prime1') and d.get('prime2') and
      d.get('exponent1') and d.get('exponent2') and d.get('coefficient') and
      isinstance(d['prime1'], (int, long)) and
      isinstance(d['prime2'], (int, long)) and
      isinstance(d['modulus'], (int, long)) and
      2 < d['prime2'] < d['prime1'] < d['modulus'])


def get_rsa_der(d):
  return der_value((0, d['modulus'], d['public_exponent'], d['private_exponent'], d['prime1'], d['prime2'], d['exponent1'], d['exponent2'], d['coefficient']))


OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'  # rsaEncryption.


def convert_rsa_data(d, format='pem'):
  if isinstance(d, bytes):
    data = d
    if data.startswith(b'\x30'):
      pass  # !! Remove der2 header.
    elif data.startswith(b'-') or data[:1].isspace():
      raise ValueError('pem input not supported.')  # TODO(pts): Add support.
    else:
      raise ValueError('Expected der input.')
  elif isinstance(d, dict):
    if not is_rsa_private_key_complete(d):
      d = get_rsa_private_key(**d)
    data = get_rsa_der(d)
  else:
    raise TypeError
  if format == 'der':
    return data
  if format == 'pem':
    return b'-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n' % base64_encode(data)
  data = der_value((0, (der_oid(OID_RSA_ENCRYPTION), None), der_bytes(data)))
  if format == 'der2':
    return data
  if format == 'pem2':
    return b'-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n' % base64_encode(data)
  raise ValueError('Unknown RSA data format: %r' % (format,))


# ---


# 4096-bit key:
#public_exponent =  0x10001
#private_exponent = 0x008b682fe7a6df6222834386916067c48c40f8d532d52095445df4514c6e8b57ddfc812c85494091d38762ce8e8395f8f7c79d45d93df3e9015cc48e384e9765e8027d95c9a10aad38f4603364f46c61729a885571a63b32cecf4ca61a4014194add9b646cfec5cd7b78bdcf42fe1b258719534d706bbb8959d76f0d2a7abb25bdea39f86d1eb99bac226c726576c710e6cdf3be2dacb0d0167efc8a55e90fa96bce06eff12e0bd182621a5c8452bd5cd93c10f47e5a367623c417182c2068d00e7cca386602e9338a6eaaa8ab1050d6b9cdfef8674b56eca06b94e65a38c404d881c97cd97863dd3fbd09b688d881431ec75c9d7d727242b5cfa8cdee0ee6371de50d4c4285c090baeebe8751242a6b9ee9fda9fa5a6fd93db08e52fcb92226bbd589ab5f31b01669e0c812fbae47fc1812f1619502a3cf8b3e592394f3b466293e9d355d17fef3b39afc137460f1e60746f62260a2fe2f419385e9a762cb18ad9a79d497ac9476d8c0a9fac34ea90729749ff6e0efbfe9f2976d1c6274a5e694118dfd1eb941f76f125ca85e1983bb8733dde8cca23f16fc0047f1a4b4959788764e1efdd2b292a8f54c6f11eea8bef5a262b75b9282f5528da9a7a7bf2d69cabee340238ad11d0f49333422fbded7df44d83b5a9c4d34e9b2113a7bf6a169a490afbcb48b12db4bf4920db53c376b7d7bcbd9a9859eeaaa31672bd38fb2f825
#prime1 =           0x00f0710459cd01a206f4c4dbb8cd591c3f240c887c11bfef21d00cb0b973e4adafb373c1fec279252771e78f0cde980723f97c5457e72648e2eafaea98414eb8448be103e0e276c0a772735e9eacb45e2ac8d03562ea2c72fb1b83c101e6355aae764dff1fcd7f18ea3c8c384052e64cff91a23085d1149d9ed6c7e3bfa1e09735d6ebfeb981ed168c4942f384570c54b07c01e61afc9277a959147715ec17a29fc0a41e4c694813f755ba4f5ba21f221c0ac7d44e499e0856c66c1330b4d32f09e7b4f3bb47f6a564d381872e0d2b1b3c3dc132d31500e7fa7bde2c302a217bedba964d2dbc02d84b47cbe8bafac184963e65b028d9f6fa71b975440d0513aea3
#prime2 =           0x00d4d51ee89043051536d581b984820ba0925c006b327490ac010b27780b4612873d7c1ed1accd4e994518a51252de889410c8fefdb7fbfe05352506897a8e507eda7063ff33adda4020be19a32b26d13f35c0aa92d67cdca855561feb0e8d929481e29ce65906acc37eb514ac9b4743d8b6605ff6caa4abb1372c5b6d3c15639fc441cf5780f5dce59dc71c04e41b396bb84162b6d26f33b83ab6f63635f637d0dc36d263ba78c1bd0ba80726cda6ec09e90cd4933948ec17d43762f54c3fa8d33ed90b62204f35ba8b9354addbf227437ff5fe7f6602a3377f48a5e4db2fadd97b02ffe394a9cf2ffef2bbb1c0fa7b495306a4191aa9f4c5fea6dc9ec5c41263
#exponent1 =        0x00350667943a4ed2e1bfd72e31aa2fadb80b062c8f5806c100eef5ed7f689c94e53ba91aae494b183383be3260ff31fdd9242b141ab2a251cea14da6b0df2e321b03d222ddd473a5f7079983d37078f28f72ebdfea298495f2e4d5809a1f9fc298d9044870460c727d2dcf2a949cf3a72571839839daab363b925850d4b1296b8f770f62849cafa19a5c89c4547a3200f74ed1c86249332fea8bf7a46f943a7e25c7012aa165527cfcbdce31b41ea3c90cf01fb3a5743cc2d008404b572179b554f4e18622d63301b4a3a45c207eccf3dbac2ed03b96d535539b3f9af5204574243052f7404fc73cd6154655d3ee7b00f775594da924b07ff8d69292e86027400b
#exponent2 =        0x0067ce8f25c57f3ad26f0d5219873cdaa8f5d9f3c65534af7f857ec8406fd73ca043e7ef2c3b8963c5b402e2387ebcd586ca6d0e99f78bec08e433ebed501e6bba83967fdf7078625416e441a2e92024bd1cdd9d14c392e119258e3d412bb6f780819d6303a2f6737b62a8b5adbe8ad2d7b7946819fa1ab937557ec8150e522c66379615a84b591fe5cabfdbb5b300685056ed6555606c26a0bbda935a3b959d01bcf6ec45022575f15be7179de07e82f00e80588a7a4d4c020f5af864464d626dae60b481a6da9b8d2218b91b9784938c03b49aedce7688df3fb0d2613e5b12035a514b37d841beb15d3b4d3ad4b21741db4208f5c9a08da7a89e004b5c90569b
#coefficient =      0x00396271522fa813889c95111768c398ba21768328c008f9fca9868502ab1fa1bfc7c73f8ece306ec4a449a91862047d6a6bf55bdb7175e8ae5337180be4cd0ebcc6ee8ffd225b5d0a83da0f3a0256eed6232cfde243543a6601352c53c6d2028db854870169d912d7c3914aa0698fa7fadf60b713847de69e090325502a5a417c75b272d0aeb81eb19d31980a08850a30bd04d1a33093fee0fcc2a3b76e62c0834fa4633437f0a77143eba92b76590223e5f6de7488c171381593848c6b6a0d5b8a95f09c0aee821fa2bc057ba8f2751f3e9d105937c60782d1e8e7933cddf1876e697d44c93fc1e1006568e66d0d79b2cb4882d4dd618991a5a3a7b1b2c1362a
#modulus =          0x00c7e5c2aaa8e9e8be55a16277ab0c60d5249c0996578ae1e63261664c3b08e42ce69af7817255d0c2b3cc640b311e7d76cf1a346839905195045a040c819bd2227300130a1a7ebe78609d69c0170a1362acd57e2a605b035ae9a4904d322621079b1484640269b7a115997ced3a1fb06e7e298ad57746a7395d9b09893e7d63c48f802132cd9c530a80af0d253705dfb1212adae3a29642aeeb18c52103ec8b5a731e65af07a6b1667e385f9208c7e41ef22085f9af955b373ecc96b04b20b24a9f835ec1787b4e5471a459b7ac23a3e8e1ee8c915081a1ee4a55a13c2b077f6c58aa7db1e4badcf670c24ff14c179146e573eb99db77bdf3a83bce808185b194953d5ccc78be03ec7665c6bab34a7fe45bfb306efa8d1e5e9dc2403ef66a1da2cae70b7026c5223782ae28252eac0103715e2e4341b9040d46f886bd198ccd832fddc3b977fa73015535927ed7813f62453722a3e64e3cec779bda447cd2455da608ea227cd35dfc69db9bced50d9c3d826bc8db25d7657a6268084dd8c267e36cc7882df00ae583deab706c558a60509dbfeb4a098c4df466c44bd86e7d28e53480f2c855b7b6688ebd1e1d1c4ae0e61718f114c88e274833dbdb058721d37aa43ff1e0d33dd14fc4463d86f0fe7f32fb438204536f67f25cfc7d85d6eb58e5122533ee69c7eda10f95b1a5217a23c25ef57292b571d60919ee20737cafff09

# !! Python 3.0.
d = get_rsa_private_key(
    modulus=0x00c7e5c2aaa8e9e8be55a16277ab0c60d5249c0996578ae1e63261664c3b08e42ce69af7817255d0c2b3cc640b311e7d76cf1a346839905195045a040c819bd2227300130a1a7ebe78609d69c0170a1362acd57e2a605b035ae9a4904d322621079b1484640269b7a115997ced3a1fb06e7e298ad57746a7395d9b09893e7d63c48f802132cd9c530a80af0d253705dfb1212adae3a29642aeeb18c52103ec8b5a731e65af07a6b1667e385f9208c7e41ef22085f9af955b373ecc96b04b20b24a9f835ec1787b4e5471a459b7ac23a3e8e1ee8c915081a1ee4a55a13c2b077f6c58aa7db1e4badcf670c24ff14c179146e573eb99db77bdf3a83bce808185b194953d5ccc78be03ec7665c6bab34a7fe45bfb306efa8d1e5e9dc2403ef66a1da2cae70b7026c5223782ae28252eac0103715e2e4341b9040d46f886bd198ccd832fddc3b977fa73015535927ed7813f62453722a3e64e3cec779bda447cd2455da608ea227cd35dfc69db9bced50d9c3d826bc8db25d7657a6268084dd8c267e36cc7882df00ae583deab706c558a60509dbfeb4a098c4df466c44bd86e7d28e53480f2c855b7b6688ebd1e1d1c4ae0e61718f114c88e274833dbdb058721d37aa43ff1e0d33dd14fc4463d86f0fe7f32fb438204536f67f25cfc7d85d6eb58e5122533ee69c7eda10f95b1a5217a23c25ef57292b571d60919ee20737cafff09,
    public_exponent=0x10001,
    prime1=0x00f0710459cd01a206f4c4dbb8cd591c3f240c887c11bfef21d00cb0b973e4adafb373c1fec279252771e78f0cde980723f97c5457e72648e2eafaea98414eb8448be103e0e276c0a772735e9eacb45e2ac8d03562ea2c72fb1b83c101e6355aae764dff1fcd7f18ea3c8c384052e64cff91a23085d1149d9ed6c7e3bfa1e09735d6ebfeb981ed168c4942f384570c54b07c01e61afc9277a959147715ec17a29fc0a41e4c694813f755ba4f5ba21f221c0ac7d44e499e0856c66c1330b4d32f09e7b4f3bb47f6a564d381872e0d2b1b3c3dc132d31500e7fa7bde2c302a217bedba964d2dbc02d84b47cbe8bafac184963e65b028d9f6fa71b975440d0513aea3)
der = convert_rsa_data(d, 'der')
pem = convert_rsa_data(d, 'pem')
der2 = convert_rsa_data(d, 'der2')
pem2 = convert_rsa_data(d, 'pem2')
assert convert_rsa_data(der, 'der') == der
#!!assert convert_rsa_data(pem, 'der') == der
#!!assert convert_rsa_data(der2, 'der') == der
#!!assert convert_rsa_data(pem2, 'der') == der

open('t.der', 'wb').write(der)
open('t.pem', 'wb').write(pem)
open('t2.der', 'wb').write(der2)
open('t2.pem', 'wb').write(pem2)


public_exponent, private_exponent, prime1, prime2, exponent1, exponent2, coefficient, modulus = (
    d['public_exponent'], d['private_exponent'], d['prime1'], d['prime2'], d['exponent1'], d['exponent2'], d['coefficient'], d['modulus'])
# All 256, i.e. about 2048 bits.
print(len('%x' % prime1) >> 1) 
print(len('%x' % prime2) >> 1)
print(len('%x' % exponent1) >> 1)
print(len('%x' % exponent2) >> 1)
print(len('%x' % coefficient) >> 1)

assert prime1 > prime2
assert modulus == prime1 * prime2
assert private_exponent * public_exponent % ((prime1 - 1) * (prime2 - 1)) == 1
assert 1 <= public_exponent < (prime1 - 1) * (prime2 - 1)
assert 1 <= private_exponent < (prime1 - 1) * (prime2 - 1)
assert private_exponent == modinv(public_exponent, (prime1 - 1) * (prime2 - 1))
assert public_exponent == modinv(private_exponent, (prime1 - 1) * (prime2 - 1))
assert coefficient == modinv(prime2, prime1)
assert prime2 == modinv(coefficient, prime1)
assert (coefficient * prime2) % prime1 == 1
assert exponent1 == private_exponent % (prime1 - 1)
assert exponent2 == private_exponent % (prime2 - 1)
gcdm = gcd(prime1 - 1, prime2 - 1)
lcm = (prime1 - 1) * (prime2 - 1) // gcdm
assert 1 <= public_exponent < lcm
assert gcd(public_exponent, lcm) == 1
# Equivalent to private_exponent2 for pow(msg, ..., modulus) purposes.
private_exponent2 = private_exponent % lcm
assert 1 <= private_exponent2 < lcm
assert gcd(private_exponent, lcm) == 1
print(gcd(prime1 - 1, prime2 - 1))  # Can be larger than 1.
assert private_exponent2 == crt2(exponent1, prime1 - 1, exponent2, (prime2 - 1) // gcdm)
assert private_exponent2 == crt2(exponent1, (prime1 - 1) // gcdm, exponent2, (prime2 - 1))




#@0 30820942: d=0 hl=4 l=2370=0x0942 cons/SEQUENCE
#  @4 0201: d=1 hl=2 l=1 prim/INTEGER zero
#    00: INTEGER data prefix
#  @7 300D: d=1 hl=2 l=13 cons/SEQUENCE
#    @9 0609: d=2 hl=2 l=9 prim/OBJECT rsaEncryption
#      2A864886F70D010101: ASN.1 OID (object identifier) 1.2.840.113549.1.1.1 == {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) rsaEncryption(1)} http://oid-info.com/get/1.2.840.113549.1.1.1
#    @20 0500: d=2 hl=2 l=0 prim/NULL
#  @22 0482092C: d=1 hl=4 l=2348=0x092c prim/OCTET_STRING
#    30820928...B2C1362A: PRKINTS data (same as above)


print('OK0')
# Takes a few (10) seconds, depends on random.
#assert prime1 == recover_rsa_prime1_from_exponents(modulus, private_exponent, public_exponent)

print('OK1')
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

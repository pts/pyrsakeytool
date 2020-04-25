rsakeytool.py: Convert between various RSA private key formats
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
rsakeytool.py is a command-line tool written in Python to convert between
various RSA private key formats (e.g. PEM, DER, Microsoft, Dropbear). The
command-line interface is compatible with of `openssl rsa ...'.

Extra features over `openssl rsa ...':

* rsakeytool.py can read and write more file formats (e.g. Dropbear).
* rsakeytool.py autodetects the input file format.
* rsakeytool.py can calculate some missing fields (e.g. if 2 of
  (modulus, prime1, prime2) is known, the 3rd one is calculated).
* rsakeytool.py supports PEM `-----BEGIN PRIVATE KEY-----' output conveniently
  with the `-outform pem2' flag. The default is PEM
  ``-----BEGIN RSA PRIVATE KEY-----', matching the `openssl rsa' default.

Missing features:

* Reading or writing encrypted (password-protected) RSA private key files.
* Reading or writing public-key cryptography key files other than RSA.
* Reading or writing RSA public key formats (with the private key fields).
* Reading, writing or verifying X.509 certificates (cert.pem, *.csr,
  `openssl x509') and certificate requests.
* Many command-line flags `openssl rsa ...'.

rsakeytool.py works with any version of Python >= 2.4. It has been
tested with 2.4, 2.7, 3.0 and 3.8. rsakeytool.py uses only a few standard
Python modules, it doesn't need any extensions (e.g. pyasn1 or PyCrypto).

FYI PEM is the key file format of web servers (for https://) and OpenSSH.
PEM is an ASCII (with base64) format. DER is the eqivalent binary format.
Both of these formats serialize values using ASN.1.

Example usage for dumping hex integer values to stdout:

  $ ./rsakeytool.py rsa -in ~/.ssh/id_rsa -dump

Example usage for file format conversion:

  $ ./rsakeytool.py rsa -in ~/.ssh/id_rsa -out rsa.msblob -outform msblob

Example usage for key recovery (all fields from 3 fields):

  $ (echo 'e = 5'; echo 'd = 493'; echo 'n = 0x29B') >re.hexa
  $ ./rsakeytool.py rsa -in re.hexa -dump
  modulus = 0x29b
  public_exponent = 0x5
  private_exponent = 0x1ed
  prime1 = 0x1d
  prime2 = 0x17
  exponent1 = 0x11
  exponent2 = 0x9
  coefficient = 0x18

__END__

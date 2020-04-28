rsakeytool.py: Convert between various RSA private key formats
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
rsakeytool.py is a command-line tool written in Python to convert between
various RSA private key formats (e.g. PEM, DER, Microsoft, OpenSSH,
Dropbear, GPG 2.2 .key, GPG 2.3 .key). It can also read RSA private keys
exported from GPG. The command-line interface is compatible with of
`openssl rsa ...'.

Extra features over `openssl rsa ...':

* rsakeytool.py can read and write more file formats (e.g. Dropbear).
* rsakeytool.py autodetects the input file format.
* rsakeytool.py can calculate some missing fields (e.g. if 2 of
  (modulus, prime1, prime2) is known, the 3rd one is calculated).
* rsakeytool.py supports
  PEM `-----BEGIN PRIVATE KEY-----' (`openssl genpkey') output conveniently
  with the `-outform pem2' flag. The default is
  PEM ``-----BEGIN RSA PRIVATE KEY-----' (`openssl genrsa'), matching the
  `openssl rsa' default.

Missing features:

* Reading or writing encrypted (password-protected) RSA private key files.
* Reading or writing public-key cryptography key files other than RSA.
* Reading or writing RSA public key formats (with the private key fields).
* Reading, writing or verifying X.509 certificates (cert.pem, *.csr,
  `openssl x509') and certificate requests.
* Many command-line flags of `openssl rsa ...'.

rsakeytool.py works with any version of Python >= 2.4. It has been
tested with 2.4, 2.7, 3.0 and 3.8. rsakeytool.py uses only a few standard
Python modules, it doesn't need any extensions (e.g. pyasn1 or PyCrypto).

FYI PEM is the private key file format used by web servers (for https://).
OpenSSH also supports PEM, but recent versions of ssh-keygen generate the
custom OpenSSH format (~/.ssh/id_rsa). PEM is an ASCII (with base64) format.
DER is the eqivalent binary format. Both of these formats serialize values
using ASN.1. Other formats (such as OpeNSSH and Microsoft) dont' use ASN.1.

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

Example for exporting an RSA private key from GPG (using
https://github.com/pts/gpg-export-secret-key-unprotected):

  $ ./gpg-export-secret-key-unprotected MYKEY |
    gpg --list-packets --debug 0x2 >gpgkeys.lst
  $ ./rsakeytool.py rsa -in gpgkeys.lst -dump
  info: found RSA private key: -keyid 1111111111111111
  info: found RSA private key: -keyid AAAAAAAAAAAAAAAA
  ...
  $ ./rsakeytool.py rsa -in gpgkeys.lst -keyid 1111111111111111 -dump
  modulus = 0x...
  ...

__END__

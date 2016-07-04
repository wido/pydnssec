import math
import struct
import base64

import Crypto.PublicKey.RSA
import Crypto.PublicKey.DSA
import Crypto.Util.number
import Crypto.Hash.SHA
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512
import Crypto.Signature.PKCS1_v1_5

import dns.exception
import dns.hash
import dns.name
import dns.node
import dns.rdataset
import dns.rdata
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.RRSIG
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
import dns.rdtypes.ANY.NSEC3PARAM


class UnsupportedAlgorithm(dns.exception.DNSException):
    pass


class ValidationFailure(dns.exception.DNSException):
    pass


class NSEC3Collision(dns.exception.DNSException):
    pass

RSAMD5 = 1
DH = 2
DSA = 3
RSASHA1 = 5
DSANSEC3SHA1 = 6
RSASHA1NSEC3SHA1 = 7
RSASHA256 = 8
RSASHA512 = 10
ECCGOST = 12
ECDSAP256SHA256 = 13
ECDSAP384SHA384 = 14
INDIRECT = 252
PRIVATEDNS = 253
PRIVATEOID = 254

DNSKEY_FLAG_NONE = 0
DNSKEY_FLAG_ZONEKEY = 256
DNSKEY_FLAG_SEP = 1

NSEC3_ALG_SHA1 = 1
NSEC3_FLAG_NONE = 0
NSEC3_FLAG_OPTOUT = 1


_algorithm_by_text = {
    'RSAMD5': RSAMD5,
    'DH': DH,
    'DSA': DSA,
    'RSASHA1': RSASHA1,
    'DSANSEC3SHA1': DSANSEC3SHA1,
    'RSASHA1NSEC3SHA1': RSASHA1NSEC3SHA1,
    'RSASHA256': RSASHA256,
    'RSASHA512': RSASHA512,
    'ECCGOST': ECCGOST,
    'ECDSAP256SHA256': ECDSAP256SHA256,
    'ECDSAP384SHA384': ECDSAP384SHA384,
    'INDIRECT': INDIRECT,
    'PRIVATEDNS': PRIVATEDNS,
    'PRIVATEOID': PRIVATEOID,
}

_algorithm_by_value = dict([(y, x) for x, y in _algorithm_by_text.items()])


def algorithm_from_text(text):
    value = _algorithm_by_text.get(text.upper())
    if value is None:
        value = int(text)
    return value


def algorithm_to_text(value):
    text = _algorithm_by_value.get(value)
    if text is None:
        text = str(value)
    return text


def _is_rsa(algorithm):
    return algorithm in (RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512)


def _is_dsa(algorithm):
    return algorithm in (DSA, DSANSEC3SHA1)


def _is_sha1(algorithm):
    return algorithm in (DSA, RSASHA1,
                         DSANSEC3SHA1, RSASHA1NSEC3SHA1)


def _is_sha256(algorithm):
    return algorithm == RSASHA256


def _is_sha384(algorithm):
    return algorithm == ECDSAP384SHA384


def _is_sha512(algorithm):
    return algorithm == RSASHA512


def _rsa2dnskey(key):
    octets = ''
    explen = int(math.ceil(math.log(key.e, 2)/8))
    if explen > 255:
        octets = "\x00"
    octets += Crypto.Util.number.long_to_bytes(explen).decode() + \
              Crypto.Util.number.long_to_bytes(key.e).decode() + \
              Crypto.Util.number.long_to_bytes(key.n).decode('ISO-8859-1')
    return octets


def _dnskey2rsa(keyptr):
    (b,) = struct.unpack('!B', keyptr[0:1]) 
    keyptr = keyptr[1:]
    if b == 0: 
        (b,) = struct.unpack('!H', keyptr[0:2]) 
        keyptr = keyptr[2:]
    rsa_e = keyptr[0:b] 
    rsa_n = keyptr[b:]
    return rsa_e, rsa_n

_file_privkey_rsa = \
"""Private-key-format: v1.2
Algorithm: %(alg)d (%(algtxt)s)
Modulus: %(n)s
PublicExponent: %(e)s
PrivateExponent: %(d)s
Prime1: %(p)s
Prime2: %(q)s
Exponent1: %(dmp1)s
Exponent2: %(dmq1)s
Coefficient: %(u)s
"""


class PrivateDNSKEY(dns.rdtypes.ANY.DNSKEY.DNSKEY):
    @classmethod
    def generate(cls, flags, algorithm, bits=None, rdclass=dns.rdataclass.IN,
                 rdtype=dns.rdatatype.DNSKEY, protocol=3):
        if _is_rsa(algorithm):
            if not isinstance(bits, int):
                raise ValidationFailure("For RSA key generation, key size in "
                                        "bits must be provided")
            key = Crypto.PublicKey.RSA.generate(bits)
            private = key.exportKey(format='PEM')
            public = _rsa2dnskey(key)
        else:
            raise ValidationFailure("Unknown algorithm %d" % algorithm)

        return cls(flags, algorithm, public, private, rdclass, rdtype,protocol)

    @classmethod
    def from_file(cls, flags, algorithm, privkey, rdclass=dns.rdataclass.IN,
                  rdtype=dns.rdatatype.DNSKEY, protocol=3):
        key = Crypto.PublicKey.RSA.importKey(privkey)
        public = _rsa2dnskey(key)

        return cls(flags, algorithm, public, privkey, rdclass, rdtype, protocol)

    def __init__(self, flags, algorithm, key, privkey=None,
                 rdclass=dns.rdataclass.IN, rdtype=dns.rdatatype.DNSKEY, 
                 protocol=3):
        super(PrivateDNSKEY, self).__init__(rdclass, rdtype, flags, protocol,
                                            algorithm, key)
        self.privkey = privkey
        self._tag = None

    def get_pubkey(self):
        return dns.rdtypes.ANY.DNSKEY.DNSKEY(self.rdclass, self.rdtype,
                                             self.flags, self.protocol,
                                             self.algorithm, self.key.encode())

    def bits(self):
        if _is_rsa(self.algorithm):
            rsa_e, rsa_n = _dnskey2rsa(self.key)
            return len(rsa_n)*8
        else:
            raise ValidationFailure("Unknown algorithm %d" % self.algorithm)

    def __str__(self):
        if not _is_rsa(self.algorithm):
            raise ValidationFailure("Unknown algorithm %d" % self.algorithm)

        # Prepare key data
        key = Crypto.PublicKey.RSA.importKey(self.privkey)
        keydata = dict(alg=self.algorithm,
                       algtxt=algorithm_to_text(self.algorithm))
        for field in key.keydata:
            f = getattr(key, field)
            f = Crypto.Util.number.long_to_bytes(f)
            keydata[field] = base64.b64encode(f).decode()

        dmp1 = Crypto.Util.number.long_to_bytes(key.d % (key.p - 1))
        keydata['dmp1'] = base64.b64encode(dmp1).decode()
        dmq1 = Crypto.Util.number.long_to_bytes(key.d % (key.p - 1))
        keydata['dmq1'] = base64.b64encode(dmq1).decode()

        return _file_privkey_rsa % keydata

from __future__ import annotations

import calendar
import datetime
import functools
import sys
import typing
import warnings
from base64 import b16encode
from collections.abc import Iterable, Sequence
from functools import partial
from typing import (
    Any,
    Callable,
    Union,
)

if sys.version_info >= (3, 13):
    from warnings import deprecated
elif sys.version_info < (3, 8):
    _T = typing.TypeVar("T")

    def deprecated(msg: str, **kwargs: object) -> Callable[[_T], _T]:
        pass
else:
    from typing_extensions import deprecated

from cryptography import utils, x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)

from OpenSSL._util import StrOrBytesPath
from OpenSSL._util import (
    byte_string as _byte_string,
)
from OpenSSL._util import (
    exception_from_error_queue as _exception_from_error_queue,
)
from OpenSSL._util import (
    ffi as _ffi,
)
from OpenSSL._util import (
    lib as _lib,
)
from OpenSSL._util import (
    make_assert as _make_assert,
)
from OpenSSL._util import (
    path_bytes as _path_bytes,
)

__all__ = [
    "FILETYPE_ASN1",
    "FILETYPE_PEM",
    "FILETYPE_TEXT",
    "TYPE_DSA",
    "TYPE_RSA",
    "X509",
    "Error",
    "PKey",
    "X509Extension",
    "X509Name",
    "X509Req",
    "X509Store",
    "X509StoreContext",
    "X509StoreContextError",
    "X509StoreFlags",
    "dump_certificate",
    "dump_certificate_request",
    "dump_privatekey",
    "dump_publickey",
    "get_elliptic_curve",
    "get_elliptic_curves",
    "load_certificate",
    "load_certificate_request",
    "load_privatekey",
    "load_publickey",
]


_PrivateKey = Union[
    dsa.DSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    rsa.RSAPrivateKey,
]
_PublicKey = Union[
    dsa.DSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    rsa.RSAPublicKey,
]
_Key = Union[_PrivateKey, _PublicKey]
PassphraseCallableT = Union[bytes, Callable[..., bytes]]


FILETYPE_PEM: int = _lib.SSL_FILETYPE_PEM
FILETYPE_ASN1: int = _lib.SSL_FILETYPE_ASN1

# TODO This was an API mistake.  OpenSSL has no such constant.
FILETYPE_TEXT = 2**16 - 1

TYPE_RSA: int = _lib.EVP_PKEY_RSA
TYPE_DSA: int = _lib.EVP_PKEY_DSA
TYPE_DH: int = _lib.EVP_PKEY_DH
TYPE_EC: int = _lib.EVP_PKEY_EC


class Error(Exception):
    """
    An error occurred in an `OpenSSL.crypto` API.
    """


_raise_current_error = partial(_exception_from_error_queue, Error)
_openssl_assert = _make_assert(Error)


def _new_mem_buf(buffer: bytes | None = None) -> Any:
    """
    Allocate a new OpenSSL memory BIO.

    Arrange for the garbage collector to clean it up automatically.

    :param buffer: None or some bytes to use to put into the BIO so that they
        can be read out.
    """
    def free():
        pass
    pass


def _bio_to_string(bio: Any) -> bytes:
    """
    Copy the contents of an OpenSSL BIO object into a Python byte string.
    """
    pass


def _set_asn1_time(boundary: Any, when: bytes) -> None:
    """
    The the time value of an ASN1 time object.

    @param boundary: An ASN1_TIME pointer (or an object safely
        castable to that type) which will have its value set.
    @param when: A string representation of the desired time value.

    @raise TypeError: If C{when} is not a L{bytes} string.
    @raise ValueError: If C{when} does not represent a time in the required
        format.
    @raise RuntimeError: If the time value cannot be set for some other
        (unspecified) reason.
    """
    pass


def _new_asn1_time(when: bytes) -> Any:
    """
    Behaves like _set_asn1_time but returns a new ASN1_TIME object.

    @param when: A string representation of the desired time value.

    @raise TypeError: If C{when} is not a L{bytes} string.
    @raise ValueError: If C{when} does not represent a time in the required
        format.
    @raise RuntimeError: If the time value cannot be set for some other
        (unspecified) reason.
    """
    pass


def _get_asn1_time(timestamp: Any) -> bytes | None:
    """
    Retrieve the time value of an ASN1 time object.

    @param timestamp: An ASN1_GENERALIZEDTIME* (or an object safely castable to
        that type) from which the time value will be retrieved.

    @return: The time value from C{timestamp} as a L{bytes} string in a certain
        format.  Or C{None} if the object contains no time value.
    """
    pass


class _X509NameInvalidator:
    def __init__(self) -> None:
        self._names: list[X509Name] = []

    def add(self, name: X509Name) -> None:
        pass

    def clear(self) -> None:
        pass


class PKey:
    """
    A class representing an DSA or RSA public key or key pair.
    """

    _only_public = False
    _initialized = True

    def __init__(self) -> None:
        pkey = _lib.EVP_PKEY_new()
        self._pkey = _ffi.gc(pkey, _lib.EVP_PKEY_free)
        self._initialized = False

    def to_cryptography_key(self) -> _Key:
        """
        Export as a ``cryptography`` key.

        :rtype: One of ``cryptography``'s `key interfaces`_.

        .. _key interfaces: https://cryptography.io/en/latest/hazmat/\
            primitives/asymmetric/rsa/#key-interfaces

        .. versionadded:: 16.1.0
        """
        pass

    @classmethod
    def from_cryptography_key(cls, crypto_key: _Key) -> PKey:
        """
        Construct based on a ``cryptography`` *crypto_key*.

        :param crypto_key: A ``cryptography`` key.
        :type crypto_key: One of ``cryptography``'s `key interfaces`_.

        :rtype: PKey

        .. versionadded:: 16.1.0
        """
        pass

    def generate_key(self, type: int, bits: int) -> None:
        """
        Generate a key pair of the given type, with the given number of bits.

        This generates a key "into" the this object.

        :param type: The key type.
        :type type: :py:data:`TYPE_RSA` or :py:data:`TYPE_DSA`
        :param bits: The number of bits.
        :type bits: :py:data:`int` ``>= 0``
        :raises TypeError: If :py:data:`type` or :py:data:`bits` isn't
            of the appropriate type.
        :raises ValueError: If the number of bits isn't an integer of
            the appropriate size.
        :return: ``None``
        """
        pass

    def check(self) -> bool:
        """
        Check the consistency of an RSA private key.

        This is the Python equivalent of OpenSSL's ``RSA_check_key``.

        :return: ``True`` if key is consistent.

        :raise OpenSSL.crypto.Error: if the key is inconsistent.

        :raise TypeError: if the key is of a type which cannot be checked.
            Only RSA keys can currently be checked.
        """
        pass

    def type(self) -> int:
        """
        Returns the type of the key

        :return: The type of the key.
        """
        pass

    def bits(self) -> int:
        """
        Returns the number of bits of the key

        :return: The number of bits of the key.
        """
        pass


class _EllipticCurve:
    """
    A representation of a supported elliptic curve.

    @cvar _curves: :py:obj:`None` until an attempt is made to load the curves.
        Thereafter, a :py:type:`set` containing :py:type:`_EllipticCurve`
        instances each of which represents one curve supported by the system.
    @type _curves: :py:type:`NoneType` or :py:type:`set`
    """

    _curves = None

    def __ne__(self, other: Any) -> bool:
        """
        Implement cooperation with the right-hand side argument of ``!=``.

        Python 3 seems to have dropped this cooperation in this very narrow
        circumstance.
        """
        if isinstance(other, _EllipticCurve):
            return super().__ne__(other)
        return NotImplemented

    @classmethod
    def _load_elliptic_curves(cls, lib: Any) -> set[_EllipticCurve]:
        """
        Get the curves supported by OpenSSL.

        :param lib: The OpenSSL library binding object.

        :return: A :py:type:`set` of ``cls`` instances giving the names of the
            elliptic curves the underlying library supports.
        """
        pass

    @classmethod
    def _get_elliptic_curves(cls, lib: Any) -> set[_EllipticCurve]:
        """
        Get, cache, and return the curves supported by OpenSSL.

        :param lib: The OpenSSL library binding object.

        :return: A :py:type:`set` of ``cls`` instances giving the names of the
            elliptic curves the underlying library supports.
        """
        pass

    @classmethod
    def from_nid(cls, lib: Any, nid: int) -> _EllipticCurve:
        """
        Instantiate a new :py:class:`_EllipticCurve` associated with the given
        OpenSSL NID.

        :param lib: The OpenSSL library binding object.

        :param nid: The OpenSSL NID the resulting curve object will represent.
            This must be a curve NID (and not, for example, a hash NID) or
            subsequent operations will fail in unpredictable ways.
        :type nid: :py:class:`int`

        :return: The curve object.
        """
        pass

    def __init__(self, lib: Any, nid: int, name: str) -> None:
        """
        :param _lib: The :py:mod:`cryptography` binding instance used to
            interface with OpenSSL.

        :param _nid: The OpenSSL NID identifying the curve this object
            represents.
        :type _nid: :py:class:`int`

        :param name: The OpenSSL short name identifying the curve this object
            represents.
        :type name: :py:class:`unicode`
        """
        self._lib = lib
        self._nid = nid
        self.name = name

    def __repr__(self) -> str:
        return f"<Curve {self.name!r}>"

    def _to_EC_KEY(self) -> Any:
        """
        Create a new OpenSSL EC_KEY structure initialized to use this curve.

        The structure is automatically garbage collected when the Python object
        is garbage collected.
        """
        pass


@deprecated(
    "get_elliptic_curves is deprecated. You should use the APIs in "
    "cryptography instead."
)
def get_elliptic_curves() -> set[_EllipticCurve]:
    """
    Return a set of objects representing the elliptic curves supported in the
    OpenSSL build in use.

    The curve objects have a :py:class:`unicode` ``name`` attribute by which
    they identify themselves.

    The curve objects are useful as values for the argument accepted by
    :py:meth:`Context.set_tmp_ecdh` to specify which elliptical curve should be
    used for ECDHE key exchange.
    """
    pass


@deprecated(
    "get_elliptic_curve is deprecated. You should use the APIs in "
    "cryptography instead."
)
def get_elliptic_curve(name: str) -> _EllipticCurve:
    """
    Return a single curve object selected by name.

    See :py:func:`get_elliptic_curves` for information about curve objects.

    :param name: The OpenSSL short name identifying the curve object to
        retrieve.
    :type name: :py:class:`unicode`

    If the named curve is not supported then :py:class:`ValueError` is raised.
    """
    pass


@functools.total_ordering
class X509Name:
    """
    An X.509 Distinguished Name.

    :ivar countryName: The country of the entity.
    :ivar C: Alias for  :py:attr:`countryName`.

    :ivar stateOrProvinceName: The state or province of the entity.
    :ivar ST: Alias for :py:attr:`stateOrProvinceName`.

    :ivar localityName: The locality of the entity.
    :ivar L: Alias for :py:attr:`localityName`.

    :ivar organizationName: The organization name of the entity.
    :ivar O: Alias for :py:attr:`organizationName`.

    :ivar organizationalUnitName: The organizational unit of the entity.
    :ivar OU: Alias for :py:attr:`organizationalUnitName`

    :ivar commonName: The common name of the entity.
    :ivar CN: Alias for :py:attr:`commonName`.

    :ivar emailAddress: The e-mail address of the entity.
    """

    def __init__(self, name: X509Name) -> None:
        """
        Create a new X509Name, copying the given X509Name instance.

        :param name: The name to copy.
        :type name: :py:class:`X509Name`
        """
        name = _lib.X509_NAME_dup(name._name)
        self._name: Any = _ffi.gc(name, _lib.X509_NAME_free)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            return super().__setattr__(name, value)

        # Note: we really do not want str subclasses here, so we do not use
        # isinstance.
        if type(name) is not str:
            raise TypeError(
                f"attribute name must be string, not "
                f"'{type(value).__name__:.200}'"
            )

        nid = _lib.OBJ_txt2nid(_byte_string(name))
        if nid == _lib.NID_undef:
            try:
                _raise_current_error()
            except Error:
                pass
            raise AttributeError("No such attribute")

        # If there's an old entry for this NID, remove it
        for i in range(_lib.X509_NAME_entry_count(self._name)):
            ent = _lib.X509_NAME_get_entry(self._name, i)
            ent_obj = _lib.X509_NAME_ENTRY_get_object(ent)
            ent_nid = _lib.OBJ_obj2nid(ent_obj)
            if nid == ent_nid:
                ent = _lib.X509_NAME_delete_entry(self._name, i)
                _lib.X509_NAME_ENTRY_free(ent)
                break

        if isinstance(value, str):
            value = value.encode("utf-8")

        add_result = _lib.X509_NAME_add_entry_by_NID(
            self._name, nid, _lib.MBSTRING_UTF8, value, len(value), -1, 0
        )
        if not add_result:
            _raise_current_error()

    def __getattr__(self, name: str) -> str | None:
        """
        Find attribute. An X509Name object has the following attributes:
        countryName (alias C), stateOrProvince (alias ST), locality (alias L),
        organization (alias O), organizationalUnit (alias OU), commonName
        (alias CN) and more...
        """
        nid = _lib.OBJ_txt2nid(_byte_string(name))
        if nid == _lib.NID_undef:
            # This is a bit weird.  OBJ_txt2nid indicated failure, but it seems
            # a lower level function, a2d_ASN1_OBJECT, also feels the need to
            # push something onto the error queue.  If we don't clean that up
            # now, someone else will bump into it later and be quite confused.
            # See lp#314814.
            try:
                _raise_current_error()
            except Error:
                pass
            raise AttributeError("No such attribute")

        entry_index = _lib.X509_NAME_get_index_by_NID(self._name, nid, -1)
        if entry_index == -1:
            return None

        entry = _lib.X509_NAME_get_entry(self._name, entry_index)
        data = _lib.X509_NAME_ENTRY_get_data(entry)

        result_buffer = _ffi.new("unsigned char**")
        data_length = _lib.ASN1_STRING_to_UTF8(result_buffer, data)
        _openssl_assert(data_length >= 0)

        try:
            result = _ffi.buffer(result_buffer[0], data_length)[:].decode(
                "utf-8"
            )
        finally:
            # XXX untested
            _lib.OPENSSL_free(result_buffer[0])
        return result

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, X509Name):
            return NotImplemented

        return _lib.X509_NAME_cmp(self._name, other._name) == 0

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, X509Name):
            return NotImplemented

        return _lib.X509_NAME_cmp(self._name, other._name) < 0

    def __repr__(self) -> str:
        """
        String representation of an X509Name
        """
        result_buffer = _ffi.new("char[]", 512)
        format_result = _lib.X509_NAME_oneline(
            self._name, result_buffer, len(result_buffer)
        )
        _openssl_assert(format_result != _ffi.NULL)

        return "<X509Name object '{}'>".format(
            _ffi.string(result_buffer).decode("utf-8"),
        )

    def hash(self) -> int:
        """
        Return an integer representation of the first four bytes of the
        MD5 digest of the DER representation of the name.

        This is the Python equivalent of OpenSSL's ``X509_NAME_hash``.

        :return: The (integer) hash of this name.
        :rtype: :py:class:`int`
        """
        pass

    def der(self) -> bytes:
        """
        Return the DER encoding of this name.

        :return: The DER encoded form of this name.
        :rtype: :py:class:`bytes`
        """
        pass

    def get_components(self) -> list[tuple[bytes, bytes]]:
        """
        Returns the components of this name, as a sequence of 2-tuples.

        :return: The components of this name.
        :rtype: :py:class:`list` of ``name, value`` tuples.
        """
        pass


@deprecated(
    "X509Extension support in pyOpenSSL is deprecated. You should use the "
    "APIs in cryptography."
)
class X509Extension:
    """
    An X.509 v3 certificate extension.

    .. deprecated:: 23.3.0
       Use cryptography's X509 APIs instead.
    """

    def __init__(
        self,
        type_name: bytes,
        critical: bool,
        value: bytes,
        subject: X509 | None = None,
        issuer: X509 | None = None,
    ) -> None:
        """
        Initializes an X509 extension.

        :param type_name: The name of the type of extension_ to create.
        :type type_name: :py:data:`bytes`

        :param bool critical: A flag indicating whether this is a critical
            extension.

        :param value: The OpenSSL textual representation of the extension's
            value.
        :type value: :py:data:`bytes`

        :param subject: Optional X509 certificate to use as subject.
        :type subject: :py:class:`X509`

        :param issuer: Optional X509 certificate to use as issuer.
        :type issuer: :py:class:`X509`

        .. _extension: https://www.openssl.org/docs/manmaster/man5/
            x509v3_config.html#STANDARD-EXTENSIONS
        """
        ctx = _ffi.new("X509V3_CTX*")

        # A context is necessary for any extension which uses the r2i
        # conversion method.  That is, X509V3_EXT_nconf may segfault if passed
        # a NULL ctx. Start off by initializing most of the fields to NULL.
        _lib.X509V3_set_ctx(ctx, _ffi.NULL, _ffi.NULL, _ffi.NULL, _ffi.NULL, 0)

        # We have no configuration database - but perhaps we should (some
        # extensions may require it).
        _lib.X509V3_set_ctx_nodb(ctx)

        # Initialize the subject and issuer, if appropriate.  ctx is a local,
        # and as far as I can tell none of the X509V3_* APIs invoked here steal
        # any references, so no need to mess with reference counts or
        # duplicates.
        if issuer is not None:
            if not isinstance(issuer, X509):
                raise TypeError("issuer must be an X509 instance")
            ctx.issuer_cert = issuer._x509
        if subject is not None:
            if not isinstance(subject, X509):
                raise TypeError("subject must be an X509 instance")
            ctx.subject_cert = subject._x509

        if critical:
            # There are other OpenSSL APIs which would let us pass in critical
            # separately, but they're harder to use, and since value is already
            # a pile of crappy junk smuggling a ton of utterly important
            # structured data, what's the point of trying to avoid nasty stuff
            # with strings? (However, X509V3_EXT_i2d in particular seems like
            # it would be a better API to invoke.  I do not know where to get
            # the ext_struc it desires for its last parameter, though.)
            value = b"critical," + value

        extension = _lib.X509V3_EXT_nconf(_ffi.NULL, ctx, type_name, value)
        if extension == _ffi.NULL:
            _raise_current_error()
        self._extension = _ffi.gc(extension, _lib.X509_EXTENSION_free)

    @property
    def _nid(self) -> Any:
        pass

    _prefixes: typing.ClassVar[dict[int, str]] = {
        _lib.GEN_EMAIL: "email",
        _lib.GEN_DNS: "DNS",
        _lib.GEN_URI: "URI",
    }

    def _subjectAltNameString(self) -> str:
        pass

    def __str__(self) -> str:
        """
        :return: a nice text representation of the extension
        """
        if _lib.NID_subject_alt_name == self._nid:
            return self._subjectAltNameString()

        bio = _new_mem_buf()
        print_result = _lib.X509V3_EXT_print(bio, self._extension, 0, 0)
        _openssl_assert(print_result != 0)

        return _bio_to_string(bio).decode("utf-8")

    def get_critical(self) -> bool:
        """
        Returns the critical field of this X.509 extension.

        :return: The critical field.
        """
        pass

    def get_short_name(self) -> bytes:
        """
        Returns the short type name of this X.509 extension.

        The result is a byte string such as :py:const:`b"basicConstraints"`.

        :return: The short type name.
        :rtype: :py:data:`bytes`

        .. versionadded:: 0.12
        """
        pass

    def get_data(self) -> bytes:
        """
        Returns the data of the X509 extension, encoded as ASN.1.

        :return: The ASN.1 encoded data of this X509 extension.
        :rtype: :py:data:`bytes`

        .. versionadded:: 0.12
        """
        pass


@deprecated(
    "CSR support in pyOpenSSL is deprecated. You should use the APIs "
    "in cryptography."
)
class X509Req:
    """
    An X.509 certificate signing requests.

    .. deprecated:: 24.2.0
       Use `cryptography.x509.CertificateSigningRequest` instead.
    """

    def __init__(self) -> None:
        req = _lib.X509_REQ_new()
        self._req = _ffi.gc(req, _lib.X509_REQ_free)
        # Default to version 0.
        self.set_version(0)

    def to_cryptography(self) -> x509.CertificateSigningRequest:
        """
        Export as a ``cryptography`` certificate signing request.

        :rtype: ``cryptography.x509.CertificateSigningRequest``

        .. versionadded:: 17.1.0
        """
        pass

    @classmethod
    def from_cryptography(
        cls, crypto_req: x509.CertificateSigningRequest
    ) -> X509Req:
        """
        Construct based on a ``cryptography`` *crypto_req*.

        :param crypto_req: A ``cryptography`` X.509 certificate signing request
        :type crypto_req: ``cryptography.x509.CertificateSigningRequest``

        :rtype: X509Req

        .. versionadded:: 17.1.0
        """
        pass

    def set_pubkey(self, pkey: PKey) -> None:
        """
        Set the public key of the certificate signing request.

        :param pkey: The public key to use.
        :type pkey: :py:class:`PKey`

        :return: ``None``
        """
        pass

    def get_pubkey(self) -> PKey:
        """
        Get the public key of the certificate signing request.

        :return: The public key.
        :rtype: :py:class:`PKey`
        """
        pass

    def set_version(self, version: int) -> None:
        """
        Set the version subfield (RFC 2986, section 4.1) of the certificate
        request.

        :param int version: The version number.
        :return: ``None``
        """
        pass

    def get_version(self) -> int:
        """
        Get the version subfield (RFC 2459, section 4.1.2.1) of the certificate
        request.

        :return: The value of the version subfield.
        :rtype: :py:class:`int`
        """
        pass

    def get_subject(self) -> X509Name:
        """
        Return the subject of this certificate signing request.

        This creates a new :class:`X509Name` that wraps the underlying subject
        name field on the certificate signing request. Modifying it will modify
        the underlying signing request, and will have the effect of modifying
        any other :class:`X509Name` that refers to this subject.

        :return: The subject of this certificate signing request.
        :rtype: :class:`X509Name`
        """
        pass

    def add_extensions(self, extensions: Iterable[X509Extension]) -> None:
        """
        Add extensions to the certificate signing request.

        :param extensions: The X.509 extensions to add.
        :type extensions: iterable of :py:class:`X509Extension`
        :return: ``None``
        """
        pass

    def get_extensions(self) -> list[X509Extension]:
        """
        Get X.509 extensions in the certificate signing request.

        :return: The X.509 extensions in this request.
        :rtype: :py:class:`list` of :py:class:`X509Extension` objects.

        .. versionadded:: 0.15
        """
        pass

    def sign(self, pkey: PKey, digest: str) -> None:
        """
        Sign the certificate signing request with this key and digest type.

        :param pkey: The key pair to sign with.
        :type pkey: :py:class:`PKey`
        :param digest: The name of the message digest to use for the signature,
            e.g. :py:data:`"sha256"`.
        :type digest: :py:class:`str`
        :return: ``None``
        """
        pass

    def verify(self, pkey: PKey) -> bool:
        """
        Verifies the signature on this certificate signing request.

        :param PKey key: A public key.

        :return: ``True`` if the signature is correct.
        :rtype: bool

        :raises OpenSSL.crypto.Error: If the signature is invalid or there is a
            problem verifying the signature.
        """
        pass


class X509:
    """
    An X.509 certificate.
    """

    def __init__(self) -> None:
        x509 = _lib.X509_new()
        _openssl_assert(x509 != _ffi.NULL)
        self._x509 = _ffi.gc(x509, _lib.X509_free)

        self._issuer_invalidator = _X509NameInvalidator()
        self._subject_invalidator = _X509NameInvalidator()

    @classmethod
    def _from_raw_x509_ptr(cls, x509: Any) -> X509:
        pass

    def to_cryptography(self) -> x509.Certificate:
        """
        Export as a ``cryptography`` certificate.

        :rtype: ``cryptography.x509.Certificate``

        .. versionadded:: 17.1.0
        """
        pass

    @classmethod
    def from_cryptography(cls, crypto_cert: x509.Certificate) -> X509:
        """
        Construct based on a ``cryptography`` *crypto_cert*.

        :param crypto_key: A ``cryptography`` X.509 certificate.
        :type crypto_key: ``cryptography.x509.Certificate``

        :rtype: X509

        .. versionadded:: 17.1.0
        """
        pass

    def set_version(self, version: int) -> None:
        """
        Set the version number of the certificate. Note that the
        version value is zero-based, eg. a value of 0 is V1.

        :param version: The version number of the certificate.
        :type version: :py:class:`int`

        :return: ``None``
        """
        pass

    def get_version(self) -> int:
        """
        Return the version number of the certificate.

        :return: The version number of the certificate.
        :rtype: :py:class:`int`
        """
        pass

    def get_pubkey(self) -> PKey:
        """
        Get the public key of the certificate.

        :return: The public key.
        :rtype: :py:class:`PKey`
        """
        pass

    def set_pubkey(self, pkey: PKey) -> None:
        """
        Set the public key of the certificate.

        :param pkey: The public key.
        :type pkey: :py:class:`PKey`

        :return: :py:data:`None`
        """
        pass

    def sign(self, pkey: PKey, digest: str) -> None:
        """
        Sign the certificate with this key and digest type.

        :param pkey: The key to sign with.
        :type pkey: :py:class:`PKey`

        :param digest: The name of the message digest to use.
        :type digest: :py:class:`str`

        :return: :py:data:`None`
        """
        pass

    def get_signature_algorithm(self) -> bytes:
        """
        Return the signature algorithm used in the certificate.

        :return: The name of the algorithm.
        :rtype: :py:class:`bytes`

        :raises ValueError: If the signature algorithm is undefined.

        .. versionadded:: 0.13
        """
        pass

    def digest(self, digest_name: str) -> bytes:
        """
        Return the digest of the X509 object.

        :param digest_name: The name of the digest algorithm to use.
        :type digest_name: :py:class:`str`

        :return: The digest of the object, formatted as
            :py:const:`b":"`-delimited hex pairs.
        :rtype: :py:class:`bytes`
        """
        pass

    def subject_name_hash(self) -> int:
        """
        Return the hash of the X509 subject.

        :return: The hash of the subject.
        :rtype: :py:class:`int`
        """
        pass

    def set_serial_number(self, serial: int) -> None:
        """
        Set the serial number of the certificate.

        :param serial: The new serial number.
        :type serial: :py:class:`int`

        :return: :py:data`None`
        """
        pass

    def get_serial_number(self) -> int:
        """
        Return the serial number of this certificate.

        :return: The serial number.
        :rtype: int
        """
        pass

    def gmtime_adj_notAfter(self, amount: int) -> None:
        """
        Adjust the time stamp on which the certificate stops being valid.

        :param int amount: The number of seconds by which to adjust the
            timestamp.
        :return: ``None``
        """
        pass

    def gmtime_adj_notBefore(self, amount: int) -> None:
        """
        Adjust the timestamp on which the certificate starts being valid.

        :param amount: The number of seconds by which to adjust the timestamp.
        :return: ``None``
        """
        pass

    def has_expired(self) -> bool:
        """
        Check whether the certificate has expired.

        :return: ``True`` if the certificate has expired, ``False`` otherwise.
        :rtype: bool
        """
        pass

    def _get_boundary_time(self, which: Any) -> bytes | None:
        pass

    def get_notBefore(self) -> bytes | None:
        """
        Get the timestamp at which the certificate starts being valid.

        The timestamp is formatted as an ASN.1 TIME::

            YYYYMMDDhhmmssZ

        :return: A timestamp string, or ``None`` if there is none.
        :rtype: bytes or NoneType
        """
        pass

    def _set_boundary_time(
        self, which: Callable[..., Any], when: bytes
    ) -> None:
        pass

    def set_notBefore(self, when: bytes) -> None:
        """
        Set the timestamp at which the certificate starts being valid.

        The timestamp is formatted as an ASN.1 TIME::

            YYYYMMDDhhmmssZ

        :param bytes when: A timestamp string.
        :return: ``None``
        """
        pass

    def get_notAfter(self) -> bytes | None:
        """
        Get the timestamp at which the certificate stops being valid.

        The timestamp is formatted as an ASN.1 TIME::

            YYYYMMDDhhmmssZ

        :return: A timestamp string, or ``None`` if there is none.
        :rtype: bytes or NoneType
        """
        pass

    def set_notAfter(self, when: bytes) -> None:
        """
        Set the timestamp at which the certificate stops being valid.

        The timestamp is formatted as an ASN.1 TIME::

            YYYYMMDDhhmmssZ

        :param bytes when: A timestamp string.
        :return: ``None``
        """
        pass

    def _get_name(self, which: Any) -> X509Name:
        pass

    def _set_name(self, which: Any, name: X509Name) -> None:
        pass

    def get_issuer(self) -> X509Name:
        """
        Return the issuer of this certificate.

        This creates a new :class:`X509Name` that wraps the underlying issuer
        name field on the certificate. Modifying it will modify the underlying
        certificate, and will have the effect of modifying any other
        :class:`X509Name` that refers to this issuer.

        :return: The issuer of this certificate.
        :rtype: :class:`X509Name`
        """
        pass

    def set_issuer(self, issuer: X509Name) -> None:
        """
        Set the issuer of this certificate.

        :param issuer: The issuer.
        :type issuer: :py:class:`X509Name`

        :return: ``None``
        """
        pass

    def get_subject(self) -> X509Name:
        """
        Return the subject of this certificate.

        This creates a new :class:`X509Name` that wraps the underlying subject
        name field on the certificate. Modifying it will modify the underlying
        certificate, and will have the effect of modifying any other
        :class:`X509Name` that refers to this subject.

        :return: The subject of this certificate.
        :rtype: :class:`X509Name`
        """
        pass

    def set_subject(self, subject: X509Name) -> None:
        """
        Set the subject of this certificate.

        :param subject: The subject.
        :type subject: :py:class:`X509Name`

        :return: ``None``
        """
        pass

    def get_extension_count(self) -> int:
        """
        Get the number of extensions on this certificate.

        :return: The number of extensions.
        :rtype: :py:class:`int`

        .. versionadded:: 0.12
        """
        pass

    def add_extensions(self, extensions: Iterable[X509Extension]) -> None:
        """
        Add extensions to the certificate.

        :param extensions: The extensions to add.
        :type extensions: An iterable of :py:class:`X509Extension` objects.
        :return: ``None``
        """
        pass

    def get_extension(self, index: int) -> X509Extension:
        """
        Get a specific extension of the certificate by index.

        Extensions on a certificate are kept in order. The index
        parameter selects which extension will be returned.

        :param int index: The index of the extension to retrieve.
        :return: The extension at the specified index.
        :rtype: :py:class:`X509Extension`
        :raises IndexError: If the extension index was out of bounds.

        .. versionadded:: 0.12
        """
        pass


class X509StoreFlags:
    """
    Flags for X509 verification, used to change the behavior of
    :class:`X509Store`.

    See `OpenSSL Verification Flags`_ for details.

    .. _OpenSSL Verification Flags:
        https://www.openssl.org/docs/manmaster/man3/X509_VERIFY_PARAM_set_flags.html
    """

    CRL_CHECK: int = _lib.X509_V_FLAG_CRL_CHECK
    CRL_CHECK_ALL: int = _lib.X509_V_FLAG_CRL_CHECK_ALL
    IGNORE_CRITICAL: int = _lib.X509_V_FLAG_IGNORE_CRITICAL
    X509_STRICT: int = _lib.X509_V_FLAG_X509_STRICT
    ALLOW_PROXY_CERTS: int = _lib.X509_V_FLAG_ALLOW_PROXY_CERTS
    POLICY_CHECK: int = _lib.X509_V_FLAG_POLICY_CHECK
    EXPLICIT_POLICY: int = _lib.X509_V_FLAG_EXPLICIT_POLICY
    INHIBIT_MAP: int = _lib.X509_V_FLAG_INHIBIT_MAP
    CHECK_SS_SIGNATURE: int = _lib.X509_V_FLAG_CHECK_SS_SIGNATURE
    PARTIAL_CHAIN: int = _lib.X509_V_FLAG_PARTIAL_CHAIN


class X509Store:
    """
    An X.509 store.

    An X.509 store is used to describe a context in which to verify a
    certificate. A description of a context may include a set of certificates
    to trust, a set of certificate revocation lists, verification flags and
    more.

    An X.509 store, being only a description, cannot be used by itself to
    verify a certificate. To carry out the actual verification process, see
    :class:`X509StoreContext`.
    """

    def __init__(self) -> None:
        store = _lib.X509_STORE_new()
        self._store = _ffi.gc(store, _lib.X509_STORE_free)

    def add_cert(self, cert: X509) -> None:
        """
        Adds a trusted certificate to this store.

        Adding a certificate with this method adds this certificate as a
        *trusted* certificate.

        :param X509 cert: The certificate to add to this store.

        :raises TypeError: If the certificate is not an :class:`X509`.

        :raises OpenSSL.crypto.Error: If OpenSSL was unhappy with your
            certificate.

        :return: ``None`` if the certificate was added successfully.
        """
        pass

    def add_crl(self, crl: x509.CertificateRevocationList) -> None:
        """
        Add a certificate revocation list to this store.

        The certificate revocation lists added to a store will only be used if
        the associated flags are configured to check certificate revocation
        lists.

        .. versionadded:: 16.1.0

        :param crl: The certificate revocation list to add to this store.
        :type crl: ``cryptography.x509.CertificateRevocationList``
        :return: ``None`` if the certificate revocation list was added
            successfully.
        """
        pass

    def set_flags(self, flags: int) -> None:
        """
        Set verification flags to this store.

        Verification flags can be combined by oring them together.

        .. note::

          Setting a verification flag sometimes requires clients to add
          additional information to the store, otherwise a suitable error will
          be raised.

          For example, in setting flags to enable CRL checking a
          suitable CRL must be added to the store otherwise an error will be
          raised.

        .. versionadded:: 16.1.0

        :param int flags: The verification flags to set on this store.
            See :class:`X509StoreFlags` for available constants.
        :return: ``None`` if the verification flags were successfully set.
        """
        pass

    def set_time(self, vfy_time: datetime.datetime) -> None:
        """
        Set the time against which the certificates are verified.

        Normally the current time is used.

        .. note::

          For example, you can determine if a certificate was valid at a given
          time.

        .. versionadded:: 17.0.0

        :param datetime vfy_time: The verification time to set on this store.
        :return: ``None`` if the verification time was successfully set.
        """
        pass

    def load_locations(
        self,
        cafile: StrOrBytesPath | None,
        capath: StrOrBytesPath | None = None,
    ) -> None:
        """
        Let X509Store know where we can find trusted certificates for the
        certificate chain.  Note that the certificates have to be in PEM
        format.

        If *capath* is passed, it must be a directory prepared using the
        ``c_rehash`` tool included with OpenSSL.  Either, but not both, of
        *cafile* or *capath* may be ``None``.

        .. note::

          Both *cafile* and *capath* may be set simultaneously.

          Call this method multiple times to add more than one location.
          For example, CA certificates, and certificate revocation list bundles
          may be passed in *cafile* in subsequent calls to this method.

        .. versionadded:: 20.0

        :param cafile: In which file we can find the certificates (``bytes`` or
                       ``unicode``).
        :param capath: In which directory we can find the certificates
                       (``bytes`` or ``unicode``).

        :return: ``None`` if the locations were set successfully.

        :raises OpenSSL.crypto.Error: If both *cafile* and *capath* is ``None``
            or the locations could not be set for any reason.

        """
        pass


class X509StoreContextError(Exception):
    """
    An exception raised when an error occurred while verifying a certificate
    using `OpenSSL.X509StoreContext.verify_certificate`.

    :ivar certificate: The certificate which caused verificate failure.
    :type certificate: :class:`X509`
    """

    def __init__(
        self, message: str, errors: list[Any], certificate: X509
    ) -> None:
        super().__init__(message)
        self.errors = errors
        self.certificate = certificate


class X509StoreContext:
    """
    An X.509 store context.

    An X.509 store context is used to carry out the actual verification process
    of a certificate in a described context. For describing such a context, see
    :class:`X509Store`.

    :param X509Store store: The certificates which will be trusted for the
        purposes of any verifications.
    :param X509 certificate: The certificate to be verified.
    :param chain: List of untrusted certificates that may be used for building
        the certificate chain. May be ``None``.
    :type chain: :class:`list` of :class:`X509`
    """

    def __init__(
        self,
        store: X509Store,
        certificate: X509,
        chain: Sequence[X509] | None = None,
    ) -> None:
        self._store = store
        self._cert = certificate
        self._chain = self._build_certificate_stack(chain)

    @staticmethod
    def _build_certificate_stack(
        certificates: Sequence[X509] | None,
    ) -> None:
        def cleanup():
            pass
        pass

    @staticmethod
    def _exception_from_context(store_ctx: Any) -> X509StoreContextError:
        """
        Convert an OpenSSL native context error failure into a Python
        exception.

        When a call to native OpenSSL X509_verify_cert fails, additional
        information about the failure can be obtained from the store context.
        """
        pass

    def _verify_certificate(self) -> Any:
        """
        Verifies the certificate and runs an X509_STORE_CTX containing the
        results.

        :raises X509StoreContextError: If an error occurred when validating a
          certificate in the context. Sets ``certificate`` attribute to
          indicate which certificate caused the error.
        """
        pass

    def set_store(self, store: X509Store) -> None:
        """
        Set the context's X.509 store.

        .. versionadded:: 0.15

        :param X509Store store: The store description which will be used for
            the purposes of any *future* verifications.
        """
        pass

    def verify_certificate(self) -> None:
        """
        Verify a certificate in a context.

        .. versionadded:: 0.15

        :raises X509StoreContextError: If an error occurred when validating a
          certificate in the context. Sets ``certificate`` attribute to
          indicate which certificate caused the error.
        """
        pass

    def get_verified_chain(self) -> list[X509]:
        """
        Verify a certificate in a context and return the complete validated
        chain.

        :raises X509StoreContextError: If an error occurred when validating a
          certificate in the context. Sets ``certificate`` attribute to
          indicate which certificate caused the error.

        .. versionadded:: 20.0
        """
        pass


def load_certificate(type: int, buffer: bytes) -> X509:
    """
    Load a certificate (X509) from the string *buffer* encoded with the
    type *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)

    :param bytes buffer: The buffer the certificate is stored in

    :return: The X509 object
    """
    pass


def dump_certificate(type: int, cert: X509) -> bytes:
    """
    Dump the certificate *cert* into a buffer string encoded with the type
    *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1, or
        FILETYPE_TEXT)
    :param cert: The certificate to dump
    :return: The buffer with the dumped certificate in
    """
    pass


def dump_publickey(type: int, pkey: PKey) -> bytes:
    """
    Dump a public key to a buffer.

    :param type: The file type (one of :data:`FILETYPE_PEM` or
        :data:`FILETYPE_ASN1`).
    :param PKey pkey: The public key to dump
    :return: The buffer with the dumped key in it.
    :rtype: bytes
    """
    pass


def dump_privatekey(
    type: int,
    pkey: PKey,
    cipher: str | None = None,
    passphrase: PassphraseCallableT | None = None,
) -> bytes:
    """
    Dump the private key *pkey* into a buffer string encoded with the type
    *type*.  Optionally (if *type* is :const:`FILETYPE_PEM`) encrypting it
    using *cipher* and *passphrase*.

    :param type: The file type (one of :const:`FILETYPE_PEM`,
        :const:`FILETYPE_ASN1`, or :const:`FILETYPE_TEXT`)
    :param PKey pkey: The PKey to dump
    :param cipher: (optional) if encrypted PEM format, the cipher to use
    :param passphrase: (optional) if encrypted PEM format, this can be either
        the passphrase to use, or a callback for providing the passphrase.

    :return: The buffer with the dumped key in
    :rtype: bytes
    """
    pass


class _PassphraseHelper:
    def __init__(
        self,
        type: int,
        passphrase: PassphraseCallableT | None,
        more_args: bool = False,
        truncate: bool = False,
    ) -> None:
        if type != FILETYPE_PEM and passphrase is not None:
            raise ValueError(
                "only FILETYPE_PEM key format supports encryption"
            )
        self._passphrase = passphrase
        self._more_args = more_args
        self._truncate = truncate
        self._problems: list[Exception] = []

    @property
    def callback(self) -> Any:
        pass

    @property
    def callback_args(self) -> Any:
        pass

    def raise_if_problem(self, exceptionType: type[Exception] = Error) -> None:
        pass

    def _read_passphrase(
        self, buf: Any, size: int, rwflag: Any, userdata: Any
    ) -> int:
        pass


def load_publickey(type: int, buffer: str | bytes) -> PKey:
    """
    Load a public key from a buffer.

    :param type: The file type (one of :data:`FILETYPE_PEM`,
        :data:`FILETYPE_ASN1`).
    :param buffer: The buffer the key is stored in.
    :type buffer: A Python string object, either unicode or bytestring.
    :return: The PKey object.
    :rtype: :class:`PKey`
    """
    pass


def load_privatekey(
    type: int,
    buffer: str | bytes,
    passphrase: PassphraseCallableT | None = None,
) -> PKey:
    """
    Load a private key (PKey) from the string *buffer* encoded with the type
    *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param buffer: The buffer the key is stored in
    :param passphrase: (optional) if encrypted PEM format, this can be
                       either the passphrase to use, or a callback for
                       providing the passphrase.

    :return: The PKey object
    """
    pass


def dump_certificate_request(type: int, req: X509Req) -> bytes:
    """
    Dump the certificate request *req* into a buffer string encoded with the
    type *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param req: The certificate request to dump
    :return: The buffer with the dumped certificate request in


    .. deprecated:: 24.2.0
       Use `cryptography.x509.CertificateSigningRequest` instead.
    """
    pass


_dump_certificate_request_internal = dump_certificate_request

utils.deprecated(
    dump_certificate_request,
    __name__,
    (
        "CSR support in pyOpenSSL is deprecated. You should use the APIs "
        "in cryptography."
    ),
    DeprecationWarning,
    name="dump_certificate_request",
)


def load_certificate_request(type: int, buffer: bytes) -> X509Req:
    """
    Load a certificate request (X509Req) from the string *buffer* encoded with
    the type *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param buffer: The buffer the certificate request is stored in
    :return: The X509Req object

    .. deprecated:: 24.2.0
       Use `cryptography.x509.load_der_x509_csr` or
       `cryptography.x509.load_pem_x509_csr` instead.
    """
    pass


_load_certificate_request_internal = load_certificate_request

utils.deprecated(
    load_certificate_request,
    __name__,
    (
        "CSR support in pyOpenSSL is deprecated. You should use the APIs "
        "in cryptography."
    ),
    DeprecationWarning,
    name="load_certificate_request",
)
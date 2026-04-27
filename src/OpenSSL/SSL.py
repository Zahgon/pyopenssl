from __future__ import annotations

import os
import socket
import sys
import typing
import warnings
from collections.abc import Sequence
from errno import errorcode
from functools import partial, wraps
from itertools import chain, count
from sys import platform
from typing import Any, Callable, Optional, TypeVar
from weakref import WeakValueDictionary

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from OpenSSL._util import (
    StrOrBytesPath as _StrOrBytesPath,
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
    no_zero_allocator as _no_zero_allocator,
)
from OpenSSL._util import (
    path_bytes as _path_bytes,
)
from OpenSSL._util import (
    text_to_bytes_and_warn as _text_to_bytes_and_warn,
)
from OpenSSL.crypto import (
    FILETYPE_PEM,
    X509,
    PKey,
    X509Name,
    X509Store,
    _EllipticCurve,
    _PassphraseHelper,
    _PrivateKey,
)

__all__ = [
    "DTLS_CLIENT_METHOD",
    "DTLS_METHOD",
    "DTLS_SERVER_METHOD",
    "MODE_RELEASE_BUFFERS",
    "NO_OVERLAPPING_PROTOCOLS",
    "OPENSSL_BUILT_ON",
    "OPENSSL_CFLAGS",
    "OPENSSL_DIR",
    "OPENSSL_PLATFORM",
    "OPENSSL_VERSION",
    "OPENSSL_VERSION_NUMBER",
    "OP_ALL",
    "OP_CIPHER_SERVER_PREFERENCE",
    "OP_DONT_INSERT_EMPTY_FRAGMENTS",
    "OP_EPHEMERAL_RSA",
    "OP_MICROSOFT_BIG_SSLV3_BUFFER",
    "OP_MICROSOFT_SESS_ID_BUG",
    "OP_MSIE_SSLV2_RSA_PADDING",
    "OP_NETSCAPE_CA_DN_BUG",
    "OP_NETSCAPE_CHALLENGE_BUG",
    "OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG",
    "OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG",
    "OP_NO_COMPRESSION",
    "OP_NO_QUERY_MTU",
    "OP_NO_TICKET",
    "OP_PKCS1_CHECK_1",
    "OP_PKCS1_CHECK_2",
    "OP_SINGLE_DH_USE",
    "OP_SINGLE_ECDH_USE",
    "OP_SSLEAY_080_CLIENT_DH_BUG",
    "OP_SSLREF2_REUSE_CERT_TYPE_BUG",
    "OP_TLS_BLOCK_PADDING_BUG",
    "OP_TLS_D5_BUG",
    "OP_TLS_ROLLBACK_BUG",
    "RECEIVED_SHUTDOWN",
    "SENT_SHUTDOWN",
    "SESS_CACHE_BOTH",
    "SESS_CACHE_CLIENT",
    "SESS_CACHE_NO_AUTO_CLEAR",
    "SESS_CACHE_NO_INTERNAL",
    "SESS_CACHE_NO_INTERNAL_LOOKUP",
    "SESS_CACHE_NO_INTERNAL_STORE",
    "SESS_CACHE_OFF",
    "SESS_CACHE_SERVER",
    "SSL3_VERSION",
    "SSLEAY_BUILT_ON",
    "SSLEAY_CFLAGS",
    "SSLEAY_DIR",
    "SSLEAY_PLATFORM",
    "SSLEAY_VERSION",
    "SSL_CB_ACCEPT_EXIT",
    "SSL_CB_ACCEPT_LOOP",
    "SSL_CB_ALERT",
    "SSL_CB_CONNECT_EXIT",
    "SSL_CB_CONNECT_LOOP",
    "SSL_CB_EXIT",
    "SSL_CB_HANDSHAKE_DONE",
    "SSL_CB_HANDSHAKE_START",
    "SSL_CB_LOOP",
    "SSL_CB_READ",
    "SSL_CB_READ_ALERT",
    "SSL_CB_WRITE",
    "SSL_CB_WRITE_ALERT",
    "SSL_ST_ACCEPT",
    "SSL_ST_CONNECT",
    "SSL_ST_MASK",
    "TLS1_1_VERSION",
    "TLS1_2_VERSION",
    "TLS1_3_VERSION",
    "TLS1_VERSION",
    "TLS_CLIENT_METHOD",
    "TLS_METHOD",
    "TLS_SERVER_METHOD",
    "VERIFY_CLIENT_ONCE",
    "VERIFY_FAIL_IF_NO_PEER_CERT",
    "VERIFY_NONE",
    "VERIFY_PEER",
    "Connection",
    "Context",
    "Error",
    "OP_NO_SSLv2",
    "OP_NO_SSLv3",
    "OP_NO_TLSv1",
    "OP_NO_TLSv1_1",
    "OP_NO_TLSv1_2",
    "OP_NO_TLSv1_3",
    "SSLeay_version",
    "SSLv23_METHOD",
    "Session",
    "SysCallError",
    "TLSv1_1_METHOD",
    "TLSv1_2_METHOD",
    "TLSv1_METHOD",
    "WantReadError",
    "WantWriteError",
    "WantX509LookupError",
    "X509VerificationCodes",
    "ZeroReturnError",
]


OPENSSL_VERSION_NUMBER: int = _lib.OPENSSL_VERSION_NUMBER
OPENSSL_VERSION: int = _lib.OPENSSL_VERSION
OPENSSL_CFLAGS: int = _lib.OPENSSL_CFLAGS
OPENSSL_PLATFORM: int = _lib.OPENSSL_PLATFORM
OPENSSL_DIR: int = _lib.OPENSSL_DIR
OPENSSL_BUILT_ON: int = _lib.OPENSSL_BUILT_ON

SSLEAY_VERSION = OPENSSL_VERSION
SSLEAY_CFLAGS = OPENSSL_CFLAGS
SSLEAY_PLATFORM = OPENSSL_PLATFORM
SSLEAY_DIR = OPENSSL_DIR
SSLEAY_BUILT_ON = OPENSSL_BUILT_ON

SENT_SHUTDOWN = _lib.SSL_SENT_SHUTDOWN
RECEIVED_SHUTDOWN = _lib.SSL_RECEIVED_SHUTDOWN

SSLv23_METHOD = 3
TLSv1_METHOD = 4
TLSv1_1_METHOD = 5
TLSv1_2_METHOD = 6
TLS_METHOD = 7
TLS_SERVER_METHOD = 8
TLS_CLIENT_METHOD = 9
DTLS_METHOD = 10
DTLS_SERVER_METHOD = 11
DTLS_CLIENT_METHOD = 12

SSL3_VERSION: int = _lib.SSL3_VERSION
TLS1_VERSION: int = _lib.TLS1_VERSION
TLS1_1_VERSION: int = _lib.TLS1_1_VERSION
TLS1_2_VERSION: int = _lib.TLS1_2_VERSION
TLS1_3_VERSION: int = _lib.TLS1_3_VERSION

OP_NO_SSLv2: int = _lib.SSL_OP_NO_SSLv2
OP_NO_SSLv3: int = _lib.SSL_OP_NO_SSLv3
OP_NO_TLSv1: int = _lib.SSL_OP_NO_TLSv1
OP_NO_TLSv1_1: int = _lib.SSL_OP_NO_TLSv1_1
OP_NO_TLSv1_2: int = _lib.SSL_OP_NO_TLSv1_2
OP_NO_TLSv1_3: int = _lib.SSL_OP_NO_TLSv1_3

MODE_RELEASE_BUFFERS: int = _lib.SSL_MODE_RELEASE_BUFFERS

OP_SINGLE_DH_USE: int = _lib.SSL_OP_SINGLE_DH_USE
OP_SINGLE_ECDH_USE: int = _lib.SSL_OP_SINGLE_ECDH_USE
OP_EPHEMERAL_RSA: int = _lib.SSL_OP_EPHEMERAL_RSA
OP_MICROSOFT_SESS_ID_BUG: int = _lib.SSL_OP_MICROSOFT_SESS_ID_BUG
OP_NETSCAPE_CHALLENGE_BUG: int = _lib.SSL_OP_NETSCAPE_CHALLENGE_BUG
OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG: int = (
    _lib.SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
)
OP_SSLREF2_REUSE_CERT_TYPE_BUG: int = _lib.SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
OP_MICROSOFT_BIG_SSLV3_BUFFER: int = _lib.SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
OP_MSIE_SSLV2_RSA_PADDING: int = _lib.SSL_OP_MSIE_SSLV2_RSA_PADDING
OP_SSLEAY_080_CLIENT_DH_BUG: int = _lib.SSL_OP_SSLEAY_080_CLIENT_DH_BUG
OP_TLS_D5_BUG: int = _lib.SSL_OP_TLS_D5_BUG
OP_TLS_BLOCK_PADDING_BUG: int = _lib.SSL_OP_TLS_BLOCK_PADDING_BUG
OP_DONT_INSERT_EMPTY_FRAGMENTS: int = _lib.SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
OP_CIPHER_SERVER_PREFERENCE: int = _lib.SSL_OP_CIPHER_SERVER_PREFERENCE
OP_TLS_ROLLBACK_BUG: int = _lib.SSL_OP_TLS_ROLLBACK_BUG
OP_PKCS1_CHECK_1 = _lib.SSL_OP_PKCS1_CHECK_1
OP_PKCS1_CHECK_2: int = _lib.SSL_OP_PKCS1_CHECK_2
OP_NETSCAPE_CA_DN_BUG: int = _lib.SSL_OP_NETSCAPE_CA_DN_BUG
OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG: int = (
    _lib.SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
)
OP_NO_COMPRESSION: int = _lib.SSL_OP_NO_COMPRESSION

OP_NO_QUERY_MTU: int = _lib.SSL_OP_NO_QUERY_MTU
try:
    OP_COOKIE_EXCHANGE: int | None = _lib.SSL_OP_COOKIE_EXCHANGE
    __all__.append("OP_COOKIE_EXCHANGE")
except AttributeError:
    OP_COOKIE_EXCHANGE = None
OP_NO_TICKET: int = _lib.SSL_OP_NO_TICKET

try:
    OP_NO_RENEGOTIATION: int = _lib.SSL_OP_NO_RENEGOTIATION
    __all__.append("OP_NO_RENEGOTIATION")
except AttributeError:
    pass

try:
    OP_IGNORE_UNEXPECTED_EOF: int = _lib.SSL_OP_IGNORE_UNEXPECTED_EOF
    __all__.append("OP_IGNORE_UNEXPECTED_EOF")
except AttributeError:
    pass

try:
    OP_LEGACY_SERVER_CONNECT: int = _lib.SSL_OP_LEGACY_SERVER_CONNECT
    __all__.append("OP_LEGACY_SERVER_CONNECT")
except AttributeError:
    pass

OP_ALL: int = _lib.SSL_OP_ALL

VERIFY_PEER: int = _lib.SSL_VERIFY_PEER
VERIFY_FAIL_IF_NO_PEER_CERT: int = _lib.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
VERIFY_CLIENT_ONCE: int = _lib.SSL_VERIFY_CLIENT_ONCE
VERIFY_NONE: int = _lib.SSL_VERIFY_NONE

SESS_CACHE_OFF: int = _lib.SSL_SESS_CACHE_OFF
SESS_CACHE_CLIENT: int = _lib.SSL_SESS_CACHE_CLIENT
SESS_CACHE_SERVER: int = _lib.SSL_SESS_CACHE_SERVER
SESS_CACHE_BOTH: int = _lib.SSL_SESS_CACHE_BOTH
SESS_CACHE_NO_AUTO_CLEAR: int = _lib.SSL_SESS_CACHE_NO_AUTO_CLEAR
SESS_CACHE_NO_INTERNAL_LOOKUP: int = _lib.SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
SESS_CACHE_NO_INTERNAL_STORE: int = _lib.SSL_SESS_CACHE_NO_INTERNAL_STORE
SESS_CACHE_NO_INTERNAL: int = _lib.SSL_SESS_CACHE_NO_INTERNAL

SSL_ST_CONNECT: int = _lib.SSL_ST_CONNECT
SSL_ST_ACCEPT: int = _lib.SSL_ST_ACCEPT
SSL_ST_MASK: int = _lib.SSL_ST_MASK

SSL_CB_LOOP: int = _lib.SSL_CB_LOOP
SSL_CB_EXIT: int = _lib.SSL_CB_EXIT
SSL_CB_READ: int = _lib.SSL_CB_READ
SSL_CB_WRITE: int = _lib.SSL_CB_WRITE
SSL_CB_ALERT: int = _lib.SSL_CB_ALERT
SSL_CB_READ_ALERT: int = _lib.SSL_CB_READ_ALERT
SSL_CB_WRITE_ALERT: int = _lib.SSL_CB_WRITE_ALERT
SSL_CB_ACCEPT_LOOP: int = _lib.SSL_CB_ACCEPT_LOOP
SSL_CB_ACCEPT_EXIT: int = _lib.SSL_CB_ACCEPT_EXIT
SSL_CB_CONNECT_LOOP: int = _lib.SSL_CB_CONNECT_LOOP
SSL_CB_CONNECT_EXIT: int = _lib.SSL_CB_CONNECT_EXIT
SSL_CB_HANDSHAKE_START: int = _lib.SSL_CB_HANDSHAKE_START
SSL_CB_HANDSHAKE_DONE: int = _lib.SSL_CB_HANDSHAKE_DONE

_Buffer = typing.Union[bytes, bytearray, memoryview]
_T = TypeVar("_T")


class _NoOverlappingProtocols:
    pass


NO_OVERLAPPING_PROTOCOLS = _NoOverlappingProtocols()

# Callback types.
_ALPNSelectCallback = Callable[
    [
        "Connection",
        typing.List[bytes],
    ],
    typing.Union[bytes, _NoOverlappingProtocols],
]
_CookieGenerateCallback = Callable[["Connection"], bytes]
_CookieVerifyCallback = Callable[["Connection", bytes], bool]
_OCSPClientCallback = Callable[["Connection", bytes, Optional[_T]], bool]
_OCSPServerCallback = Callable[["Connection", Optional[_T]], bytes]
_PassphraseCallback = Callable[[int, bool, Optional[_T]], bytes]
_VerifyCallback = Callable[["Connection", X509, int, int, int], bool]


class X509VerificationCodes:
    """
    Success and error codes for X509 verification, as returned by the
    underlying ``X509_STORE_CTX_get_error()`` function and passed by pyOpenSSL
    to verification callback functions.

    See `OpenSSL Verification Errors
    <https://www.openssl.org/docs/manmaster/man3/X509_verify_cert_error_string.html#ERROR-CODES>`_
    for details.
    """

    OK = _lib.X509_V_OK
    ERR_UNABLE_TO_GET_ISSUER_CERT = _lib.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
    ERR_UNABLE_TO_GET_CRL = _lib.X509_V_ERR_UNABLE_TO_GET_CRL
    ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = (
        _lib.X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE
    )
    ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = (
        _lib.X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE
    )
    ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = (
        _lib.X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
    )
    ERR_CERT_SIGNATURE_FAILURE = _lib.X509_V_ERR_CERT_SIGNATURE_FAILURE
    ERR_CRL_SIGNATURE_FAILURE = _lib.X509_V_ERR_CRL_SIGNATURE_FAILURE
    ERR_CERT_NOT_YET_VALID = _lib.X509_V_ERR_CERT_NOT_YET_VALID
    ERR_CERT_HAS_EXPIRED = _lib.X509_V_ERR_CERT_HAS_EXPIRED
    ERR_CRL_NOT_YET_VALID = _lib.X509_V_ERR_CRL_NOT_YET_VALID
    ERR_CRL_HAS_EXPIRED = _lib.X509_V_ERR_CRL_HAS_EXPIRED
    ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = (
        _lib.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD
    )
    ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = (
        _lib.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD
    )
    ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = (
        _lib.X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD
    )
    ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = (
        _lib.X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD
    )
    ERR_OUT_OF_MEM = _lib.X509_V_ERR_OUT_OF_MEM
    ERR_DEPTH_ZERO_SELF_SIGNED_CERT = (
        _lib.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
    )
    ERR_SELF_SIGNED_CERT_IN_CHAIN = _lib.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
    ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = (
        _lib.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    )
    ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = (
        _lib.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
    )
    ERR_CERT_CHAIN_TOO_LONG = _lib.X509_V_ERR_CERT_CHAIN_TOO_LONG
    ERR_CERT_REVOKED = _lib.X509_V_ERR_CERT_REVOKED
    ERR_INVALID_CA = _lib.X509_V_ERR_INVALID_CA
    ERR_PATH_LENGTH_EXCEEDED = _lib.X509_V_ERR_PATH_LENGTH_EXCEEDED
    ERR_INVALID_PURPOSE = _lib.X509_V_ERR_INVALID_PURPOSE
    ERR_CERT_UNTRUSTED = _lib.X509_V_ERR_CERT_UNTRUSTED
    ERR_CERT_REJECTED = _lib.X509_V_ERR_CERT_REJECTED
    ERR_SUBJECT_ISSUER_MISMATCH = _lib.X509_V_ERR_SUBJECT_ISSUER_MISMATCH
    ERR_AKID_SKID_MISMATCH = _lib.X509_V_ERR_AKID_SKID_MISMATCH
    ERR_AKID_ISSUER_SERIAL_MISMATCH = (
        _lib.X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH
    )
    ERR_KEYUSAGE_NO_CERTSIGN = _lib.X509_V_ERR_KEYUSAGE_NO_CERTSIGN
    ERR_UNABLE_TO_GET_CRL_ISSUER = _lib.X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER
    ERR_UNHANDLED_CRITICAL_EXTENSION = (
        _lib.X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION
    )
    ERR_KEYUSAGE_NO_CRL_SIGN = _lib.X509_V_ERR_KEYUSAGE_NO_CRL_SIGN
    ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = (
        _lib.X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION
    )
    ERR_INVALID_NON_CA = _lib.X509_V_ERR_INVALID_NON_CA
    ERR_PROXY_PATH_LENGTH_EXCEEDED = _lib.X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED
    ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = (
        _lib.X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE
    )
    ERR_PROXY_CERTIFICATES_NOT_ALLOWED = (
        _lib.X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED
    )
    ERR_INVALID_EXTENSION = _lib.X509_V_ERR_INVALID_EXTENSION
    ERR_INVALID_POLICY_EXTENSION = _lib.X509_V_ERR_INVALID_POLICY_EXTENSION
    ERR_NO_EXPLICIT_POLICY = _lib.X509_V_ERR_NO_EXPLICIT_POLICY
    ERR_DIFFERENT_CRL_SCOPE = _lib.X509_V_ERR_DIFFERENT_CRL_SCOPE
    ERR_UNSUPPORTED_EXTENSION_FEATURE = (
        _lib.X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE
    )
    ERR_UNNESTED_RESOURCE = _lib.X509_V_ERR_UNNESTED_RESOURCE
    ERR_PERMITTED_VIOLATION = _lib.X509_V_ERR_PERMITTED_VIOLATION
    ERR_EXCLUDED_VIOLATION = _lib.X509_V_ERR_EXCLUDED_VIOLATION
    ERR_SUBTREE_MINMAX = _lib.X509_V_ERR_SUBTREE_MINMAX
    ERR_UNSUPPORTED_CONSTRAINT_TYPE = (
        _lib.X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE
    )
    ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = (
        _lib.X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX
    )
    ERR_UNSUPPORTED_NAME_SYNTAX = _lib.X509_V_ERR_UNSUPPORTED_NAME_SYNTAX
    ERR_CRL_PATH_VALIDATION_ERROR = _lib.X509_V_ERR_CRL_PATH_VALIDATION_ERROR
    ERR_HOSTNAME_MISMATCH = _lib.X509_V_ERR_HOSTNAME_MISMATCH
    ERR_EMAIL_MISMATCH = _lib.X509_V_ERR_EMAIL_MISMATCH
    ERR_IP_ADDRESS_MISMATCH = _lib.X509_V_ERR_IP_ADDRESS_MISMATCH
    ERR_APPLICATION_VERIFICATION = _lib.X509_V_ERR_APPLICATION_VERIFICATION


# Taken from https://golang.org/src/crypto/x509/root_linux.go
_CERTIFICATE_FILE_LOCATIONS = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu/Gentoo etc.
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora/RHEL 6
    "/etc/ssl/ca-bundle.pem",  # OpenSUSE
    "/etc/pki/tls/cacert.pem",  # OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # CentOS/RHEL 7
]

_CERTIFICATE_PATH_LOCATIONS = [
    "/etc/ssl/certs",  # SLES10/SLES11
]

# These values are compared to output from cffi's ffi.string so they must be
# byte strings.
_CRYPTOGRAPHY_MANYLINUX_CA_DIR = b"/opt/pyca/cryptography/openssl/certs"
_CRYPTOGRAPHY_MANYLINUX_CA_FILE = b"/opt/pyca/cryptography/openssl/cert.pem"


class Error(Exception):
    """
    An error occurred in an `OpenSSL.SSL` API.
    """


_raise_current_error = partial(_exception_from_error_queue, Error)
_openssl_assert = _make_assert(Error)


class WantReadError(Error):
    pass


class WantWriteError(Error):
    pass


class WantX509LookupError(Error):
    pass


class ZeroReturnError(Error):
    pass


class SysCallError(Error):
    pass


class _CallbackExceptionHelper:
    """
    A base class for wrapper classes that allow for intelligent exception
    handling in OpenSSL callbacks.

    :ivar list _problems: Any exceptions that occurred while executing in a
        context where they could not be raised in the normal way.  Typically
        this is because OpenSSL has called into some Python code and requires a
        return value.  The exceptions are saved to be raised later when it is
        possible to do so.
    """

    def __init__(self) -> None:
        self._problems: list[Exception] = []

    def raise_if_problem(self) -> None:
        """
        Raise an exception from the OpenSSL error queue or that was previously
        captured whe running a callback.
        """
        pass


class _VerifyHelper(_CallbackExceptionHelper):
    """
    Wrap a callback such that it can be used as a certificate verification
    callback.
    """

    def __init__(self, callback: _VerifyCallback) -> None:
        _CallbackExceptionHelper.__init__(self)

        @wraps(callback)
        def wrapper(ok, store_ctx):  # type: ignore[no-untyped-def]
            pass

        self.callback = _ffi.callback(
            "int (*)(int, X509_STORE_CTX *)", wrapper
        )


class _ALPNSelectHelper(_CallbackExceptionHelper):
    """
    Wrap a callback such that it can be used as an ALPN selection callback.
    """

    def __init__(self, callback: _ALPNSelectCallback) -> None:
        _CallbackExceptionHelper.__init__(self)

        @wraps(callback)
        def wrapper(ssl, out, outlen, in_, inlen, arg):  # type: ignore[no-untyped-def]
            pass

        self.callback = _ffi.callback(
            (
                "int (*)(SSL *, unsigned char **, unsigned char *, "
                "const unsigned char *, unsigned int, void *)"
            ),
            wrapper,
        )


class _OCSPServerCallbackHelper(_CallbackExceptionHelper):
    """
    Wrap a callback such that it can be used as an OCSP callback for the server
    side.

    Annoyingly, OpenSSL defines one OCSP callback but uses it in two different
    ways. For servers, that callback is expected to retrieve some OCSP data and
    hand it to OpenSSL, and may return only SSL_TLSEXT_ERR_OK,
    SSL_TLSEXT_ERR_FATAL, and SSL_TLSEXT_ERR_NOACK. For clients, that callback
    is expected to check the OCSP data, and returns a negative value on error,
    0 if the response is not acceptable, or positive if it is. These are
    mutually exclusive return code behaviours, and they mean that we need two
    helpers so that we always return an appropriate error code if the user's
    code throws an exception.

    Given that we have to have two helpers anyway, these helpers are a bit more
    helpery than most: specifically, they hide a few more of the OpenSSL
    functions so that the user has an easier time writing these callbacks.

    This helper implements the server side.
    """

    def __init__(self, callback: _OCSPServerCallback[Any]) -> None:
        _CallbackExceptionHelper.__init__(self)

        @wraps(callback)
        def wrapper(ssl, cdata):  # type: ignore[no-untyped-def]
            pass

        self.callback = _ffi.callback("int (*)(SSL *, void *)", wrapper)


class _OCSPClientCallbackHelper(_CallbackExceptionHelper):
    """
    Wrap a callback such that it can be used as an OCSP callback for the client
    side.

    Annoyingly, OpenSSL defines one OCSP callback but uses it in two different
    ways. For servers, that callback is expected to retrieve some OCSP data and
    hand it to OpenSSL, and may return only SSL_TLSEXT_ERR_OK,
    SSL_TLSEXT_ERR_FATAL, and SSL_TLSEXT_ERR_NOACK. For clients, that callback
    is expected to check the OCSP data, and returns a negative value on error,
    0 if the response is not acceptable, or positive if it is. These are
    mutually exclusive return code behaviours, and they mean that we need two
    helpers so that we always return an appropriate error code if the user's
    code throws an exception.

    Given that we have to have two helpers anyway, these helpers are a bit more
    helpery than most: specifically, they hide a few more of the OpenSSL
    functions so that the user has an easier time writing these callbacks.

    This helper implements the client side.
    """

    def __init__(self, callback: _OCSPClientCallback[Any]) -> None:
        _CallbackExceptionHelper.__init__(self)

        @wraps(callback)
        def wrapper(ssl, cdata):  # type: ignore[no-untyped-def]
            pass

        self.callback = _ffi.callback("int (*)(SSL *, void *)", wrapper)


class _CookieGenerateCallbackHelper(_CallbackExceptionHelper):
    def __init__(self, callback: _CookieGenerateCallback) -> None:
        _CallbackExceptionHelper.__init__(self)

        max_cookie_len = getattr(_lib, "DTLS1_COOKIE_LENGTH", 255)

        @wraps(callback)
        def wrapper(ssl, out, outlen):  # type: ignore[no-untyped-def]
            pass

        self.callback = _ffi.callback(
            "int (*)(SSL *, unsigned char *, unsigned int *)",
            wrapper,
        )


class _CookieVerifyCallbackHelper(_CallbackExceptionHelper):
    def __init__(self, callback: _CookieVerifyCallback) -> None:
        _CallbackExceptionHelper.__init__(self)

        @wraps(callback)
        def wrapper(ssl, c_cookie, cookie_len):  # type: ignore[no-untyped-def]
            pass

        self.callback = _ffi.callback(
            "int (*)(SSL *, unsigned char *, unsigned int)",
            wrapper,
        )


def _asFileDescriptor(obj: Any) -> int:
    pass


def OpenSSL_version(type: int) -> bytes:
    """
    Return a string describing the version of OpenSSL in use.

    :param type: One of the :const:`OPENSSL_` constants defined in this module.
    """
    pass


SSLeay_version = OpenSSL_version


def _make_requires(flag: int, error: str) -> Callable[[_T], _T]:
    """
    Builds a decorator that ensures that functions that rely on OpenSSL
    functions that are not present in this build raise NotImplementedError,
    rather than AttributeError coming out of cryptography.

    :param flag: A cryptography flag that guards the functions, e.g.
        ``Cryptography_HAS_NEXTPROTONEG``.
    :param error: The string to be used in the exception if the flag is false.
    """
    def _requires_decorator(func):
        def explode(*args, **kwargs):
            pass
        pass
    pass


_requires_keylog = _make_requires(
    getattr(_lib, "Cryptography_HAS_KEYLOG", 0), "Key logging not available"
)

_requires_ssl_get0_group_name = _make_requires(
    getattr(_lib, "Cryptography_HAS_SSL_GET0_GROUP_NAME", 0),
    "Getting group name is not supported by the linked OpenSSL version",
)

_requires_ssl_cookie = _make_requires(
    getattr(_lib, "Cryptography_HAS_SSL_COOKIE", 0),
    "DTLS cookie support is not available",
)


class Session:
    """
    A class representing an SSL session.  A session defines certain connection
    parameters which may be re-used to speed up the setup of subsequent
    connections.

    .. versionadded:: 0.14
    """

    _session: Any


F = TypeVar("F", bound=Callable[..., Any])


def _require_not_used(f: F) -> F:
    @wraps(f)
    def inner(self, *args, **kwargs):
        pass


class Context:
    """
    :class:`OpenSSL.SSL.Context` instances define the parameters for setting
    up new SSL connections.

    :param method: One of TLS_METHOD, TLS_CLIENT_METHOD, TLS_SERVER_METHOD,
                   DTLS_METHOD, DTLS_CLIENT_METHOD, or DTLS_SERVER_METHOD.
                   SSLv23_METHOD, TLSv1_METHOD, etc. are deprecated and should
                   not be used.
    """

    _methods: typing.ClassVar[
        dict[int, tuple[Callable[[], Any], int | None]]
    ] = {
        SSLv23_METHOD: (_lib.TLS_method, None),
        TLSv1_METHOD: (_lib.TLS_method, TLS1_VERSION),
        TLSv1_1_METHOD: (_lib.TLS_method, TLS1_1_VERSION),
        TLSv1_2_METHOD: (_lib.TLS_method, TLS1_2_VERSION),
        TLS_METHOD: (_lib.TLS_method, None),
        TLS_SERVER_METHOD: (_lib.TLS_server_method, None),
        TLS_CLIENT_METHOD: (_lib.TLS_client_method, None),
        DTLS_METHOD: (_lib.DTLS_method, None),
        DTLS_SERVER_METHOD: (_lib.DTLS_server_method, None),
        DTLS_CLIENT_METHOD: (_lib.DTLS_client_method, None),
    }

    def __init__(self, method: int) -> None:
        if not isinstance(method, int):
            raise TypeError("method must be an integer")

        try:
            method_func, version = self._methods[method]
        except KeyError:
            raise ValueError("No such protocol")

        method_obj = method_func()
        _openssl_assert(method_obj != _ffi.NULL)

        context = _lib.SSL_CTX_new(method_obj)
        _openssl_assert(context != _ffi.NULL)
        context = _ffi.gc(context, _lib.SSL_CTX_free)

        self._context = context
        self._used = False
        self._passphrase_helper: _PassphraseHelper | None = None
        self._passphrase_callback: _PassphraseCallback[Any] | None = None
        self._passphrase_userdata: Any | None = None
        self._verify_helper: _VerifyHelper | None = None
        self._verify_callback: _VerifyCallback | None = None
        self._info_callback = None
        self._keylog_callback = None
        self._tlsext_servername_callback = None
        self._app_data = None
        self._alpn_select_helper: _ALPNSelectHelper | None = None
        self._alpn_select_callback: _ALPNSelectCallback | None = None
        self._ocsp_helper: (
            _OCSPClientCallbackHelper | _OCSPServerCallbackHelper | None
        ) = None
        self._ocsp_callback: (
            _OCSPClientCallback[Any] | _OCSPServerCallback[Any] | None
        ) = None
        self._ocsp_data: Any | None = None
        self._cookie_generate_helper: _CookieGenerateCallbackHelper | None = (
            None
        )
        self._cookie_verify_helper: _CookieVerifyCallbackHelper | None = None

        self.set_mode(
            _lib.SSL_MODE_ENABLE_PARTIAL_WRITE
            | _lib.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
        )
        if version is not None:
            self.set_min_proto_version(version)
            self.set_max_proto_version(version)

    @_require_not_used
    def set_min_proto_version(self, version: int) -> None:
        """
        Set the minimum supported protocol version. Setting the minimum
        version to 0 will enable protocol versions down to the lowest version
        supported by the library.

        If the underlying OpenSSL build is missing support for the selected
        version, this method will raise an exception.
        """
        pass

    @_require_not_used
    def set_max_proto_version(self, version: int) -> None:
        """
        Set the maximum supported protocol version. Setting the maximum
        version to 0 will enable protocol versions up to the highest version
        supported by the library.

        If the underlying OpenSSL build is missing support for the selected
        version, this method will raise an exception.
        """
        pass

    @_require_not_used
    def load_verify_locations(
        self,
        cafile: _StrOrBytesPath | None,
        capath: _StrOrBytesPath | None = None,
    ) -> None:
        """
        Let SSL know where we can find trusted certificates for the certificate
        chain.  Note that the certificates have to be in PEM format.

        If capath is passed, it must be a directory prepared using the
        ``c_rehash`` tool included with OpenSSL.  Either, but not both, of
        *pemfile* or *capath* may be :data:`None`.

        :param cafile: In which file we can find the certificates (``bytes`` or
            ``str``).
        :param capath: In which directory we can find the certificates
            (``bytes`` or ``str``).

        :return: None
        """
        pass

    def _wrap_callback(
        self, callback: _PassphraseCallback[_T]
    ) -> _PassphraseHelper:
        @wraps(callback)
        def wrapper(*args, **kwargs):
            pass

    @_require_not_used
    def set_passwd_cb(
        self,
        callback: _PassphraseCallback[_T],
        userdata: _T | None = None,
    ) -> None:
        """
        Set the passphrase callback.  This function will be called
        when a private key with a passphrase is loaded.

        :param callback: The Python callback to use.  This must accept three
            positional arguments.  First, an integer giving the maximum length
            of the passphrase it may return.  If the returned passphrase is
            longer than this, it will be truncated.  Second, a boolean value
            which will be true if the user should be prompted for the
            passphrase twice and the callback should verify that the two values
            supplied are equal. Third, the value given as the *userdata*
            parameter to :meth:`set_passwd_cb`.  The *callback* must return
            a byte string. If an error occurs, *callback* should return a false
            value (e.g. an empty string).
        :param userdata: (optional) A Python object which will be given as
                         argument to the callback
        :return: None
        """
        pass

    @_require_not_used
    def set_default_verify_paths(self) -> None:
        """
        Specify that the platform provided CA certificates are to be used for
        verification purposes. This method has some caveats related to the
        binary wheels that cryptography (pyOpenSSL's primary dependency) ships:

        *   macOS will only load certificates using this method if the user has
            the ``openssl@3`` `Homebrew <https://brew.sh>`_ formula installed
            in the default location.
        *   Windows will not work.
        *   manylinux cryptography wheels will work on most common Linux
            distributions in pyOpenSSL 17.1.0 and above.  pyOpenSSL detects the
            manylinux wheel and attempts to load roots via a fallback path.

        :return: None
        """
        pass

    def _check_env_vars_set(self, dir_env_var: str, file_env_var: str) -> bool:
        """
        Check to see if the default cert dir/file environment vars are present.

        :return: bool
        """
        pass

    def _fallback_default_verify_paths(
        self, file_path: list[str], dir_path: list[str]
    ) -> None:
        """
        Default verify paths are based on the compiled version of OpenSSL.
        However, when pyca/cryptography is compiled as a manylinux wheel
        that compiled location can potentially be wrong. So, like Go, we
        will try a predefined set of paths and attempt to load roots
        from there.

        :return: None
        """
        pass

    @_require_not_used
    def use_certificate_chain_file(self, certfile: _StrOrBytesPath) -> None:
        """
        Load a certificate chain from a file.

        :param certfile: The name of the certificate chain file (``bytes`` or
            ``str``).  Must be PEM encoded.

        :return: None
        """
        pass

    @_require_not_used
    def use_certificate_file(
        self, certfile: _StrOrBytesPath, filetype: int = FILETYPE_PEM
    ) -> None:
        """
        Load a certificate from a file

        :param certfile: The name of the certificate file (``bytes`` or
            ``str``).
        :param filetype: (optional) The encoding of the file, which is either
            :const:`FILETYPE_PEM` or :const:`FILETYPE_ASN1`.  The default is
            :const:`FILETYPE_PEM`.

        :return: None
        """
        pass

    @_require_not_used
    def use_certificate(self, cert: X509 | x509.Certificate) -> None:
        """
        Load a certificate from a X509 object

        :param cert: The X509 object
        :return: None
        """
        pass

    @_require_not_used
    def add_extra_chain_cert(self, certobj: X509 | x509.Certificate) -> None:
        """
        Add certificate to chain

        :param certobj: The X509 certificate object to add to the chain
        :return: None
        """
        pass

    def _raise_passphrase_exception(self) -> None:
        pass

    @_require_not_used
    def use_privatekey_file(
        self, keyfile: _StrOrBytesPath, filetype: int = FILETYPE_PEM
    ) -> None:
        """
        Load a private key from a file

        :param keyfile: The name of the key file (``bytes`` or ``str``)
        :param filetype: (optional) The encoding of the file, which is either
            :const:`FILETYPE_PEM` or :const:`FILETYPE_ASN1`.  The default is
            :const:`FILETYPE_PEM`.

        :return: None
        """
        pass

    @_require_not_used
    def use_privatekey(self, pkey: _PrivateKey | PKey) -> None:
        """
        Load a private key from a PKey object

        :param pkey: The PKey object
        :return: None
        """
        pass

    def check_privatekey(self) -> None:
        """
        Check if the private key (loaded with :meth:`use_privatekey`) matches
        the certificate (loaded with :meth:`use_certificate`)

        :return: :data:`None` (raises :exc:`Error` if something's wrong)
        """
        pass

    @_require_not_used
    def load_client_ca(self, cafile: bytes) -> None:
        """
        Load the trusted certificates that will be sent to the client.  Does
        not actually imply any of the certificates are trusted; that must be
        configured separately.

        :param bytes cafile: The path to a certificates file in PEM format.
        :return: None
        """
        pass

    @_require_not_used
    def set_session_id(self, buf: bytes) -> None:
        """
        Set the session id to *buf* within which a session can be reused for
        this Context object.  This is needed when doing session resumption,
        because there is no way for a stored session to know which Context
        object it is associated with.

        :param bytes buf: The session id.

        :returns: None
        """
        pass

    @_require_not_used
    def set_session_cache_mode(self, mode: int) -> int:
        """
        Set the behavior of the session cache used by all connections using
        this Context.  The previously set mode is returned.  See
        :const:`SESS_CACHE_*` for details about particular modes.

        :param mode: One or more of the SESS_CACHE_* flags (combine using
            bitwise or)
        :returns: The previously set caching mode.

        .. versionadded:: 0.14
        """
        pass

    def get_session_cache_mode(self) -> int:
        """
        Get the current session cache mode.

        :returns: The currently used cache mode.

        .. versionadded:: 0.14
        """
        pass

    @_require_not_used
    def set_verify(
        self, mode: int, callback: _VerifyCallback | None = None
    ) -> None:
        """
        Set the verification flags for this Context object to *mode* and
        specify that *callback* should be used for verification callbacks.

        :param mode: The verify mode, this should be one of
            :const:`VERIFY_NONE` and :const:`VERIFY_PEER`. If
            :const:`VERIFY_PEER` is used, *mode* can be OR:ed with
            :const:`VERIFY_FAIL_IF_NO_PEER_CERT` and
            :const:`VERIFY_CLIENT_ONCE` to further control the behaviour.
        :param callback: The optional Python verification callback to use.
            This should take five arguments: A Connection object, an X509
            object, and three integer variables, which are in turn potential
            error number, error depth and return code. *callback* should
            return True if verification passes and False otherwise.
            If omitted, OpenSSL's default verification is used.
        :return: None

        See SSL_CTX_set_verify(3SSL) for further details.
        """
        pass

    @_require_not_used
    def set_verify_depth(self, depth: int) -> None:
        """
        Set the maximum depth for the certificate chain verification that shall
        be allowed for this Context object.

        :param depth: An integer specifying the verify depth
        :return: None
        """
        pass

    def get_verify_mode(self) -> int:
        """
        Retrieve the Context object's verify mode, as set by
        :meth:`set_verify`.

        :return: The verify mode
        """
        pass

    def get_verify_depth(self) -> int:
        """
        Retrieve the Context object's verify depth, as set by
        :meth:`set_verify_depth`.

        :return: The verify depth
        """
        pass

    @_require_not_used
    def load_tmp_dh(self, dhfile: _StrOrBytesPath) -> None:
        """
        Load parameters for Ephemeral Diffie-Hellman

        :param dhfile: The file to load EDH parameters from (``bytes`` or
            ``str``).

        :return: None
        """
        pass

    @_require_not_used
    def set_tmp_ecdh(self, curve: _EllipticCurve | ec.EllipticCurve) -> None:
        """
        Select a curve to use for ECDHE key exchange.

        :param curve: A curve instance from cryptography
            (:class:`~cryptogragraphy.hazmat.primitives.asymmetric.ec.EllipticCurve`).
            Alternatively (deprecated) a curve object from either
            :meth:`OpenSSL.crypto.get_elliptic_curve` or
            :meth:`OpenSSL.crypto.get_elliptic_curves`.

        :return: None
        """
        pass

    @_require_not_used
    def set_cipher_list(self, cipher_list: bytes) -> None:
        """
        Set the list of ciphers to be used in this context.

        See the OpenSSL manual for more information (e.g.
        :manpage:`ciphers(1)`).

        Note this API does not change the cipher suites used in TLS 1.3
        Use `set_tls13_ciphersuites` for that.

        :param bytes cipher_list: An OpenSSL cipher string.
        :return: None
        """
        pass

    @_require_not_used
    def set_tls13_ciphersuites(self, ciphersuites: bytes) -> None:
        """
        Set the list of TLS 1.3 ciphers to be used in this context.
        OpenSSL maintains a separate list of TLS 1.3+ ciphers to
        ciphers for TLS 1.2 and lowers.

        See the OpenSSL manual for more information (e.g.
        :manpage:`ciphers(1)`).

        :param bytes ciphersuites: An OpenSSL cipher string containing
            TLS 1.3+ ciphersuites.
        :return: None

        .. versionadded:: 25.2.0
        """
        pass

    @_require_not_used
    def set_client_ca_list(
        self, certificate_authorities: Sequence[X509Name]
    ) -> None:
        """
        Set the list of preferred client certificate signers for this server
        context.

        This list of certificate authorities will be sent to the client when
        the server requests a client certificate.

        :param certificate_authorities: a sequence of X509Names.
        :return: None

        .. versionadded:: 0.10
        """
        pass

    @_require_not_used
    def add_client_ca(
        self, certificate_authority: X509 | x509.Certificate
    ) -> None:
        """
        Add the CA certificate to the list of preferred signers for this
        context.

        The list of certificate authorities will be sent to the client when the
        server requests a client certificate.

        :param certificate_authority: certificate authority's X509 certificate.
        :return: None

        .. versionadded:: 0.10
        """
        pass

    @_require_not_used
    def set_timeout(self, timeout: int) -> None:
        """
        Set the timeout for newly created sessions for this Context object to
        *timeout*.  The default value is 300 seconds. See the OpenSSL manual
        for more information (e.g. :manpage:`SSL_CTX_set_timeout(3)`).

        :param timeout: The timeout in (whole) seconds
        :return: The previous session timeout
        """
        pass

    def get_timeout(self) -> int:
        """
        Retrieve session timeout, as set by :meth:`set_timeout`. The default
        is 300 seconds.

        :return: The session timeout
        """
        pass

    @_require_not_used
    def set_info_callback(
        self, callback: Callable[[Connection, int, int], None]
    ) -> None:
        """
        Set the information callback to *callback*. This function will be
        called from time to time during SSL handshakes.

        :param callback: The Python callback to use.  This should take three
            arguments: a Connection object and two integers.  The first integer
            specifies where in the SSL handshake the function was called, and
            the other the return code from a (possibly failed) internal
            function call.
        :return: None
        """
        def wrapper(*args, **kwargs):
            pass
        pass

    @_requires_keylog
    @_require_not_used
    def set_keylog_callback(
        self, callback: Callable[[Connection, bytes], None]
    ) -> None:
        """
        Set the TLS key logging callback to *callback*. This function will be
        called whenever TLS key material is generated or received, in order
        to allow applications to store this keying material for debugging
        purposes.

        :param callback: The Python callback to use.  This should take two
            arguments: a Connection object and a bytestring that contains
            the key material in the format used by NSS for its SSLKEYLOGFILE
            debugging output.
        :return: None
        """
        def wrapper(*args, **kwargs):
            pass
        pass

    def get_app_data(self) -> Any:
        """
        Get the application data (supplied via :meth:`set_app_data()`)

        :return: The application data
        """
        pass

    @_require_not_used
    def set_app_data(self, data: Any) -> None:
        """
        Set the application data (will be returned from get_app_data())

        :param data: Any Python object
        :return: None
        """
        pass

    def get_cert_store(self) -> X509Store | None:
        """
        Get the certificate store for the context.  This can be used to add
        "trusted" certificates without using the
        :meth:`load_verify_locations` method.

        :return: A X509Store object or None if it does not have one.
        """
        pass

    @_require_not_used
    def set_options(self, options: int) -> int:
        """
        Add options. Options set before are not cleared!
        This method should be used with the :const:`OP_*` constants.

        :param options: The options to add.
        :return: The new option bitmask.
        """
        pass

    @_require_not_used
    def set_mode(self, mode: int) -> int:
        """
        Add modes via bitmask. Modes set before are not cleared!  This method
        should be used with the :const:`MODE_*` constants.

        :param mode: The mode to add.
        :return: The new mode bitmask.
        """
        pass

    @_require_not_used
    def clear_mode(self, mode_to_clear: int) -> int:
        """
        Modes previously set cannot be overwritten without being
        cleared first. This method should be used to clear existing modes.
        """
        pass

    @_require_not_used
    def set_tlsext_servername_callback(
        self, callback: Callable[[Connection], None]
    ) -> None:
        """
        Specify a callback function to be called when clients specify a server
        name.

        :param callback: The callback function.  It will be invoked with one
            argument, the Connection instance.

        .. versionadded:: 0.13
        """
        def wrapper(*args, **kwargs):
            pass
        pass

    @_require_not_used
    def set_tlsext_use_srtp(self, profiles: bytes) -> None:
        """
        Enable support for negotiating SRTP keying material.

        :param bytes profiles: A colon delimited list of protection profile
            names, like ``b'SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32'``.
        :return: None
        """
        pass

    @_require_not_used
    def set_alpn_protos(self, protos: list[bytes]) -> None:
        """
        Specify the protocols that the client is prepared to speak after the
        TLS connection has been negotiated using Application Layer Protocol
        Negotiation.

        :param protos: A list of the protocols to be offered to the server.
            This list should be a Python list of bytestrings representing the
            protocols to offer, e.g. ``[b'http/1.1', b'spdy/2']``.
        """
        pass

    @_require_not_used
    def set_alpn_select_callback(self, callback: _ALPNSelectCallback) -> None:
        """
        Specify a callback function that will be called on the server when a
        client offers protocols using ALPN.

        :param callback: The callback function.  It will be invoked with two
            arguments: the Connection, and a list of offered protocols as
            bytestrings, e.g ``[b'http/1.1', b'spdy/2']``.  It can return
            one of those bytestrings to indicate the chosen protocol, the
            empty bytestring to terminate the TLS connection, or the
            :py:obj:`NO_OVERLAPPING_PROTOCOLS` to indicate that no offered
            protocol was selected, but that the connection should not be
            aborted.
        """
        pass

    def _set_ocsp_callback(
        self,
        helper: _OCSPClientCallbackHelper | _OCSPServerCallbackHelper,
        data: Any | None,
    ) -> None:
        """
        This internal helper does the common work for
        ``set_ocsp_server_callback`` and ``set_ocsp_client_callback``, which is
        almost all of it.
        """
        pass

    @_require_not_used
    def set_ocsp_server_callback(
        self,
        callback: _OCSPServerCallback[_T],
        data: _T | None = None,
    ) -> None:
        """
        Set a callback to provide OCSP data to be stapled to the TLS handshake
        on the server side.

        :param callback: The callback function. It will be invoked with two
            arguments: the Connection, and the optional arbitrary data you have
            provided. The callback must return a bytestring that contains the
            OCSP data to staple to the handshake. If no OCSP data is available
            for this connection, return the empty bytestring.
        :param data: Some opaque data that will be passed into the callback
            function when called. This can be used to avoid needing to do
            complex data lookups or to keep track of what context is being
            used. This parameter is optional.
        """
        pass

    @_require_not_used
    def set_ocsp_client_callback(
        self,
        callback: _OCSPClientCallback[_T],
        data: _T | None = None,
    ) -> None:
        """
        Set a callback to validate OCSP data stapled to the TLS handshake on
        the client side.

        :param callback: The callback function. It will be invoked with three
            arguments: the Connection, a bytestring containing the stapled OCSP
            assertion, and the optional arbitrary data you have provided. The
            callback must return a boolean that indicates the result of
            validating the OCSP data: ``True`` if the OCSP data is valid and
            the certificate can be trusted, or ``False`` if either the OCSP
            data is invalid or the certificate has been revoked.
        :param data: Some opaque data that will be passed into the callback
            function when called. This can be used to avoid needing to do
            complex data lookups or to keep track of what context is being
            used. This parameter is optional.
        """
        pass

    @_require_not_used
    @_requires_ssl_cookie
    def set_cookie_generate_callback(
        self, callback: _CookieGenerateCallback
    ) -> None:
        pass

    @_require_not_used
    @_requires_ssl_cookie
    def set_cookie_verify_callback(
        self, callback: _CookieVerifyCallback
    ) -> None:
        pass


class Connection:
    _reverse_mapping: typing.MutableMapping[Any, Connection] = (
        WeakValueDictionary()
    )

    def __init__(
        self, context: Context, socket: socket.socket | None = None
    ) -> None:
        """
        Create a new Connection object, using the given OpenSSL.SSL.Context
        instance and socket.

        :param context: An SSL Context to use for this connection
        :param socket: The socket to use for transport layer
        """
        if not isinstance(context, Context):
            raise TypeError("context must be a Context instance")

        context._used = True

        ssl = _lib.SSL_new(context._context)
        self._ssl = _ffi.gc(ssl, _lib.SSL_free)
        # We set SSL_MODE_AUTO_RETRY to handle situations where OpenSSL returns
        # an SSL_ERROR_WANT_READ when processing a non-application data packet
        # even though there is still data on the underlying transport.
        # See https://github.com/openssl/openssl/issues/6234 for more details.
        _lib.SSL_set_mode(self._ssl, _lib.SSL_MODE_AUTO_RETRY)
        self._context = context
        self._app_data = None

        # References to strings used for Application Layer Protocol
        # Negotiation. These strings get copied at some point but it's well
        # after the callback returns, so we have to hang them somewhere to
        # avoid them getting freed.
        self._alpn_select_callback_args: Any = None

        # Reference the verify_callback of the Context. This ensures that if
        # set_verify is called again after the SSL object has been created we
        # do not point to a dangling reference
        self._verify_helper = context._verify_helper
        self._verify_callback = context._verify_callback

        # And likewise for the cookie callbacks
        self._cookie_generate_helper = context._cookie_generate_helper
        self._cookie_verify_helper = context._cookie_verify_helper

        self._reverse_mapping[self._ssl] = self

        if socket is None:
            self._socket = None
            # Don't set up any gc for these, SSL_free will take care of them.
            self._into_ssl = _lib.BIO_new(_lib.BIO_s_mem())
            _openssl_assert(self._into_ssl != _ffi.NULL)

            self._from_ssl = _lib.BIO_new(_lib.BIO_s_mem())
            _openssl_assert(self._from_ssl != _ffi.NULL)

            _lib.SSL_set_bio(self._ssl, self._into_ssl, self._from_ssl)
        else:
            self._into_ssl = None
            self._from_ssl = None
            self._socket = socket
            set_result = _lib.SSL_set_fd(
                self._ssl, _asFileDescriptor(self._socket)
            )
            _openssl_assert(set_result == 1)

    def __getattr__(self, name: str) -> Any:
        """
        Look up attributes on the wrapped socket object if they are not found
        on the Connection object.
        """
        if self._socket is None:
            raise AttributeError(
                f"'{self.__class__.__name__}' object has no attribute '{name}'"
            )
        else:
            return getattr(self._socket, name)

    def _raise_ssl_error(self, ssl: Any, result: int) -> None:
        pass

    def get_context(self) -> Context:
        """
        Retrieve the :class:`Context` object associated with this
        :class:`Connection`.
        """
        pass

    def set_context(self, context: Context) -> None:
        """
        Switch this connection to a new session context.

        :param context: A :class:`Context` instance giving the new session
            context to use.
        """
        pass

    def get_servername(self) -> bytes | None:
        """
        Retrieve the servername extension value if provided in the client hello
        message, or None if there wasn't one.

        :return: A byte string giving the server name or :data:`None`.

        .. versionadded:: 0.13
        """
        pass

    def set_verify(
        self, mode: int, callback: _VerifyCallback | None = None
    ) -> None:
        """
        Override the Context object's verification flags for this specific
        connection. See :py:meth:`Context.set_verify` for details.
        """
        pass

    def get_verify_mode(self) -> int:
        """
        Retrieve the Connection object's verify mode, as set by
        :meth:`set_verify`.

        :return: The verify mode
        """
        pass

    def use_certificate(self, cert: X509 | x509.Certificate) -> None:
        """
        Load a certificate from a X509 object

        :param cert: The X509 object
        :return: None
        """
        pass

    def use_privatekey(self, pkey: _PrivateKey | PKey) -> None:
        """
        Load a private key from a PKey object

        :param pkey: The PKey object
        :return: None
        """
        pass

    def set_ciphertext_mtu(self, mtu: int) -> None:
        """
        For DTLS, set the maximum UDP payload size (*not* including IP/UDP
        overhead).

        Note that you might have to set :data:`OP_NO_QUERY_MTU` to prevent
        OpenSSL from spontaneously clearing this.

        :param mtu: An integer giving the maximum transmission unit.

        .. versionadded:: 21.1
        """
        pass

    def get_cleartext_mtu(self) -> int:
        """
        For DTLS, get the maximum size of unencrypted data you can pass to
        :meth:`write` without exceeding the MTU (as passed to
        :meth:`set_ciphertext_mtu`).

        :return: The effective MTU as an integer.

        .. versionadded:: 21.1
        """
        pass

    def set_tlsext_host_name(self, name: bytes) -> None:
        """
        Set the value of the servername extension to send in the client hello.

        :param name: A byte string giving the name.

        .. versionadded:: 0.13
        """
        pass

    def pending(self) -> int:
        """
        Get the number of bytes that can be safely read from the SSL buffer
        (**not** the underlying transport buffer).

        :return: The number of bytes available in the receive buffer.
        """
        pass

    def send(self, buf: _Buffer, flags: int = 0) -> int:
        """
        Send data on the connection. NOTE: If you get one of the WantRead,
        WantWrite or WantX509Lookup exceptions on this, you have to call the
        method again with the SAME buffer.

        :param buf: The string, buffer or memoryview to send
        :param flags: (optional) Included for compatibility with the socket
                      API, the value is ignored
        :return: The number of bytes written
        """
        pass

    write = send

    def sendall(self, buf: _Buffer, flags: int = 0) -> int:
        """
        Send "all" data on the connection. This calls send() repeatedly until
        all data is sent. If an error occurs, it's impossible to tell how much
        data has been sent.

        :param buf: The string, buffer or memoryview to send
        :param flags: (optional) Included for compatibility with the socket
                      API, the value is ignored
        :return: The number of bytes written
        """
        pass

    def recv(self, bufsiz: int, flags: int | None = None) -> bytes:
        """
        Receive data on the connection.

        :param bufsiz: The maximum number of bytes to read
        :param flags: (optional) The only supported flag is ``MSG_PEEK``,
            all other flags are ignored.
        :return: The string read from the Connection
        """
        pass

    read = recv

    def recv_into(
        self,
        buffer: Any,  # collections.abc.Buffer once we use Python 3.12+
        nbytes: int | None = None,
        flags: int | None = None,
    ) -> int:
        """
        Receive data on the connection and copy it directly into the provided
        buffer, rather than creating a new string.

        :param buffer: The buffer to copy into.
        :param nbytes: (optional) The maximum number of bytes to read into the
            buffer. If not present, defaults to the size of the buffer. If
            larger than the size of the buffer, is reduced to the size of the
            buffer.
        :param flags: (optional) The only supported flag is ``MSG_PEEK``,
            all other flags are ignored.
        :return: The number of bytes read into the buffer.
        """
        pass

    def _handle_bio_errors(self, bio: Any, result: int) -> typing.NoReturn:
        pass

    def bio_read(self, bufsiz: int) -> bytes:
        """
        If the Connection was created with a memory BIO, this method can be
        used to read bytes from the write end of that memory BIO.  Many
        Connection methods will add bytes which must be read in this manner or
        the buffer will eventually fill up and the Connection will be able to
        take no further actions.

        :param bufsiz: The maximum number of bytes to read
        :return: The string read.
        """
        pass

    def bio_write(self, buf: _Buffer) -> int:
        """
        If the Connection was created with a memory BIO, this method can be
        used to add bytes to the read end of that memory BIO.  The Connection
        can then read the bytes (for example, in response to a call to
        :meth:`recv`).

        :param buf: The string to put into the memory BIO.
        :return: The number of bytes written
        """
        pass

    def renegotiate(self) -> bool:
        """
        Renegotiate the session.

        :return: True if the renegotiation can be started, False otherwise
        """
        pass

    def do_handshake(self) -> None:
        """
        Perform an SSL handshake (usually called after :meth:`renegotiate` or
        one of :meth:`set_accept_state` or :meth:`set_connect_state`). This can
        raise the same exceptions as :meth:`send` and :meth:`recv`.

        :return: None.
        """
        pass

    def renegotiate_pending(self) -> bool:
        """
        Check if there's a renegotiation in progress, it will return False once
        a renegotiation is finished.

        :return: Whether there's a renegotiation in progress
        """
        pass

    def total_renegotiations(self) -> int:
        """
        Find out the total number of renegotiations.

        :return: The number of renegotiations.
        """
        pass

    def connect(self, addr: Any) -> None:
        """
        Call the :meth:`connect` method of the underlying socket and set up SSL
        on the socket, using the :class:`Context` object supplied to this
        :class:`Connection` object at creation.

        :param addr: A remote address
        :return: What the socket's connect method returns
        """
        pass

    def connect_ex(self, addr: Any) -> int:
        """
        Call the :meth:`connect_ex` method of the underlying socket and set up
        SSL on the socket, using the Context object supplied to this Connection
        object at creation. Note that if the :meth:`connect_ex` method of the
        socket doesn't return 0, SSL won't be initialized.

        :param addr: A remove address
        :return: What the socket's connect_ex method returns
        """
        pass

    def accept(self) -> tuple[Connection, Any]:
        """
        Call the :meth:`accept` method of the underlying socket and set up SSL
        on the returned socket, using the Context object supplied to this
        :class:`Connection` object at creation.

        :return: A *(conn, addr)* pair where *conn* is the new
            :class:`Connection` object created, and *address* is as returned by
            the socket's :meth:`accept`.
        """
        pass

    def DTLSv1_listen(self) -> None:
        """
        Call the OpenSSL function DTLSv1_listen on this connection. See the
        OpenSSL manual for more details.

        :return: None
        """
        pass

    def DTLSv1_get_timeout(self) -> int | None:
        """
        Determine when the DTLS SSL object next needs to perform internal
        processing due to the passage of time.

        When the returned number of seconds have passed, the
        :meth:`DTLSv1_handle_timeout` method needs to be called.

        :return: The time left in seconds before the next timeout or `None`
            if no timeout is currently active.
        """
        pass

    def DTLSv1_handle_timeout(self) -> bool:
        """
        Handles any timeout events which have become pending on a DTLS SSL
        object.

        :return: `True` if there was a pending timeout, `False` otherwise.
        """
        pass

    def bio_shutdown(self) -> None:
        """
        If the Connection was created with a memory BIO, this method can be
        used to indicate that *end of file* has been reached on the read end of
        that memory BIO.

        :return: None
        """
        pass

    def shutdown(self) -> bool:
        """
        Send the shutdown message to the Connection.

        :return: True if the shutdown completed successfully (i.e. both sides
                 have sent closure alerts), False otherwise (in which case you
                 call :meth:`recv` or :meth:`send` when the connection becomes
                 readable/writeable).
        """
        pass

    def get_cipher_list(self) -> list[str]:
        """
        Retrieve the list of ciphers used by the Connection object.

        :return: A list of native cipher strings.
        """
        pass

    def get_client_ca_list(self) -> list[X509Name]:
        """
        Get CAs whose certificates are suggested for client authentication.

        :return: If this is a server connection, the list of certificate
            authorities that will be sent or has been sent to the client, as
            controlled by this :class:`Connection`'s :class:`Context`.

            If this is a client connection, the list will be empty until the
            connection with the server is established.

        .. versionadded:: 0.10
        """
        pass

    def makefile(self, *args: Any, **kwargs: Any) -> typing.NoReturn:
        """
        The makefile() method is not implemented, since there is no dup
        semantics for SSL connections

        :raise: NotImplementedError
        """
        pass

    def get_app_data(self) -> Any:
        """
        Retrieve application data as set by :meth:`set_app_data`.

        :return: The application data
        """
        pass

    def set_app_data(self, data: Any) -> None:
        """
        Set application data

        :param data: The application data
        :return: None
        """
        pass

    def get_shutdown(self) -> int:
        """
        Get the shutdown state of the Connection.

        :return: The shutdown state, a bitvector of SENT_SHUTDOWN,
            RECEIVED_SHUTDOWN.
        """
        pass

    def set_shutdown(self, state: int) -> None:
        """
        Set the shutdown state of the Connection.

        :param state: bitvector of SENT_SHUTDOWN, RECEIVED_SHUTDOWN.
        :return: None
        """
        pass

    def get_state_string(self) -> bytes:
        """
        Retrieve a verbose string detailing the state of the Connection.

        :return: A string representing the state
        """
        pass

    def server_random(self) -> bytes | None:
        """
        Retrieve the random value used with the server hello message.

        :return: A string representing the state
        """
        pass

    def client_random(self) -> bytes | None:
        """
        Retrieve the random value used with the client hello message.

        :return: A string representing the state
        """
        pass

    def master_key(self) -> bytes | None:
        """
        Retrieve the value of the master key for this session.

        :return: A string representing the state
        """
        pass

    def export_keying_material(
        self, label: bytes, olen: int, context: bytes | None = None
    ) -> bytes:
        """
        Obtain keying material for application use.

        :param: label - a disambiguating label string as described in RFC 5705
        :param: olen - the length of the exported key material in bytes
        :param: context - a per-association context value
        :return: the exported key material bytes or None
        """
        pass

    def sock_shutdown(self, *args: Any, **kwargs: Any) -> None:
        """
        Call the :meth:`shutdown` method of the underlying socket.
        See :manpage:`shutdown(2)`.

        :return: What the socket's shutdown() method returns
        """
        pass

    @typing.overload
    def get_certificate(
        self, *, as_cryptography: typing.Literal[True]
    ) -> x509.Certificate | None:
        pass

    @typing.overload
    def get_certificate(
        self, *, as_cryptography: typing.Literal[False] = False
    ) -> X509 | None:
        pass

    def get_certificate(
        self,
        *,
        as_cryptography: typing.Literal[True] | typing.Literal[False] = False,
    ) -> X509 | x509.Certificate | None:
        """
        Retrieve the local certificate (if any)

        :param bool as_cryptography: Controls whether a
            ``cryptography.x509.Certificate`` or an ``OpenSSL.crypto.X509``
            object should be returned.

        :return: The local certificate
        """
        pass

    @typing.overload
    def get_peer_certificate(
        self, *, as_cryptography: typing.Literal[True]
    ) -> x509.Certificate | None:
        pass

    @typing.overload
    def get_peer_certificate(
        self, *, as_cryptography: typing.Literal[False] = False
    ) -> X509 | None:
        pass

    def get_peer_certificate(
        self,
        *,
        as_cryptography: typing.Literal[True] | typing.Literal[False] = False,
    ) -> X509 | x509.Certificate | None:
        """
        Retrieve the other side's certificate (if any)

        :param bool as_cryptography: Controls whether a
            ``cryptography.x509.Certificate`` or an ``OpenSSL.crypto.X509``
            object should be returned.

        :return: The peer's certificate
        """
        pass

    @staticmethod
    def _cert_stack_to_list(cert_stack: Any) -> list[X509]:
        """
        Internal helper to convert a STACK_OF(X509) to a list of X509
        instances.
        """
        pass

    @staticmethod
    def _cert_stack_to_cryptography_list(
        cert_stack: Any,
    ) -> list[x509.Certificate]:
        """
        Internal helper to convert a STACK_OF(X509) to a list of X509
        instances.
        """
        pass

    @typing.overload
    def get_peer_cert_chain(
        self, *, as_cryptography: typing.Literal[True]
    ) -> list[x509.Certificate] | None:
        pass

    @typing.overload
    def get_peer_cert_chain(
        self, *, as_cryptography: typing.Literal[False] = False
    ) -> list[X509] | None:
        pass

    def get_peer_cert_chain(
        self,
        *,
        as_cryptography: typing.Literal[True] | typing.Literal[False] = False,
    ) -> list[X509] | list[x509.Certificate] | None:
        """
        Retrieve the other side's certificate (if any)

        :param bool as_cryptography: Controls whether a list of
            ``cryptography.x509.Certificate`` or ``OpenSSL.crypto.X509``
            object should be returned.

        :return: A list of X509 instances giving the peer's certificate chain,
                 or None if it does not have one.
        """
        pass

    @typing.overload
    def get_verified_chain(
        self, *, as_cryptography: typing.Literal[True]
    ) -> list[x509.Certificate] | None:
        pass

    @typing.overload
    def get_verified_chain(
        self, *, as_cryptography: typing.Literal[False] = False
    ) -> list[X509] | None:
        pass

    def get_verified_chain(
        self,
        *,
        as_cryptography: typing.Literal[True] | typing.Literal[False] = False,
    ) -> list[X509] | list[x509.Certificate] | None:
        """
        Retrieve the verified certificate chain of the peer including the
        peer's end entity certificate. It must be called after a session has
        been successfully established. If peer verification was not successful
        the chain may be incomplete, invalid, or None.

        :param bool as_cryptography: Controls whether a list of
            ``cryptography.x509.Certificate`` or ``OpenSSL.crypto.X509``
            object should be returned.

        :return: A list of X509 instances giving the peer's verified
                 certificate chain, or None if it does not have one.

        .. versionadded:: 20.0
        """
        pass

    def want_read(self) -> bool:
        """
        Checks if more data has to be read from the transport layer to complete
        an operation.

        :return: True iff more data has to be read
        """
        pass

    def want_write(self) -> bool:
        """
        Checks if there is data to write to the transport layer to complete an
        operation.

        :return: True iff there is data to write
        """
        pass

    def set_accept_state(self) -> None:
        """
        Set the connection to work in server mode. The handshake will be
        handled automatically by read/write.

        :return: None
        """
        pass

    def set_connect_state(self) -> None:
        """
        Set the connection to work in client mode. The handshake will be
        handled automatically by read/write.

        :return: None
        """
        pass

    def get_session(self) -> Session | None:
        """
        Returns the Session currently used.

        :return: An instance of :class:`OpenSSL.SSL.Session` or
            :obj:`None` if no session exists.

        .. versionadded:: 0.14
        """
        pass

    def set_session(self, session: Session) -> None:
        """
        Set the session to be used when the TLS/SSL connection is established.

        :param session: A Session instance representing the session to use.
        :returns: None

        .. versionadded:: 0.14
        """
        pass

    def _get_finished_message(
        self, function: Callable[[Any, Any, int], int]
    ) -> bytes | None:
        """
        Helper to implement :meth:`get_finished` and
        :meth:`get_peer_finished`.

        :param function: Either :data:`SSL_get_finished`: or
            :data:`SSL_get_peer_finished`.

        :return: :data:`None` if the desired message has not yet been
            received, otherwise the contents of the message.
        """
        pass

    def get_finished(self) -> bytes | None:
        """
        Obtain the latest TLS Finished message that we sent.

        :return: The contents of the message or :obj:`None` if the TLS
            handshake has not yet completed.

        .. versionadded:: 0.15
        """
        pass

    def get_peer_finished(self) -> bytes | None:
        """
        Obtain the latest TLS Finished message that we received from the peer.

        :return: The contents of the message or :obj:`None` if the TLS
            handshake has not yet completed.

        .. versionadded:: 0.15
        """
        pass

    def get_cipher_name(self) -> str | None:
        """
        Obtain the name of the currently used cipher.

        :returns: The name of the currently used cipher or :obj:`None`
            if no connection has been established.

        .. versionadded:: 0.15
        """
        pass

    def get_cipher_bits(self) -> int | None:
        """
        Obtain the number of secret bits of the currently used cipher.

        :returns: The number of secret bits of the currently used cipher
            or :obj:`None` if no connection has been established.

        .. versionadded:: 0.15
        """
        pass

    def get_cipher_version(self) -> str | None:
        """
        Obtain the protocol version of the currently used cipher.

        :returns: The protocol name of the currently used cipher
            or :obj:`None` if no connection has been established.

        .. versionadded:: 0.15
        """
        pass

    def get_protocol_version_name(self) -> str:
        """
        Retrieve the protocol version of the current connection.

        :returns: The TLS version of the current connection, for example
            the value for TLS 1.2 would be ``TLSv1.2``or ``Unknown``
            for connections that were not successfully established.
        """
        pass

    def get_protocol_version(self) -> int:
        """
        Retrieve the SSL or TLS protocol version of the current connection.

        :returns: The TLS version of the current connection.  For example,
            it will return ``0x769`` for connections made over TLS version 1.
        """
        pass

    def set_alpn_protos(self, protos: list[bytes]) -> None:
        """
        Specify the client's ALPN protocol list.

        These protocols are offered to the server during protocol negotiation.

        :param protos: A list of the protocols to be offered to the server.
            This list should be a Python list of bytestrings representing the
            protocols to offer, e.g. ``[b'http/1.1', b'spdy/2']``.
        """
        pass

    def get_alpn_proto_negotiated(self) -> bytes:
        """
        Get the protocol that was negotiated by ALPN.

        :returns: A bytestring of the protocol name.  If no protocol has been
            negotiated yet, returns an empty bytestring.
        """
        pass

    def get_selected_srtp_profile(self) -> bytes:
        """
        Get the SRTP protocol which was negotiated.

        :returns: A bytestring of the SRTP profile name. If no profile has been
            negotiated yet, returns an empty bytestring.
        """
        pass

    @_requires_ssl_get0_group_name
    def get_group_name(self) -> str | None:
        """
        Get the name of the negotiated group for the key exchange.

        :return: A string giving the group name or :data:`None`.
        """
        pass

    def request_ocsp(self) -> None:
        """
        Called to request that the server sends stapled OCSP data, if
        available. If this is not called on the client side then the server
        will not send OCSP data. Should be used in conjunction with
        :meth:`Context.set_ocsp_client_callback`.
        """
        pass

    def set_info_callback(
        self, callback: Callable[[Connection, int, int], None]
    ) -> None:
        """
        Set the information callback to *callback*. This function will be
        called from time to time during SSL handshakes.

        :param callback: The Python callback to use.  This should take three
            arguments: a Connection object and two integers.  The first integer
            specifies where in the SSL handshake the function was called, and
            the other the return code from a (possibly failed) internal
            function call.
        :return: None
        """
        def wrapper(*args, **kwargs):
            pass
        pass
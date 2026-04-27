from __future__ import annotations

import os
import sys
import warnings
from typing import Any, Callable, NoReturn, Union

from cryptography.hazmat.bindings.openssl.binding import Binding

if sys.version_info >= (3, 9):
    StrOrBytesPath = Union[str, bytes, os.PathLike[str], os.PathLike[bytes]]
else:
    StrOrBytesPath = Union[str, bytes, os.PathLike]

binding = Binding()
ffi = binding.ffi
lib: Any = binding.lib


# This is a special CFFI allocator that does not bother to zero its memory
# after allocation. This has vastly better performance on large allocations and
# so should be used whenever we don't need the memory zeroed out.
no_zero_allocator = ffi.new_allocator(should_clear_after_alloc=False)


def text(charp: Any) -> str:
    """
    Get a native string type representing of the given CFFI ``char*`` object.

    :param charp: A C-style string represented using CFFI.

    :return: :class:`str`
    """
    pass


def exception_from_error_queue(exception_type: type[Exception]) -> NoReturn:
    """
    Convert an OpenSSL library failure into a Python exception.

    When a call to the native OpenSSL library fails, this is usually signalled
    by the return value, and an error code is stored in an error queue
    associated with the current thread. The err library provides functions to
    obtain these error codes and textual error messages.
    """
    pass


def make_assert(error: type[Exception]) -> Callable[[bool], Any]:
    """
    Create an assert function that uses :func:`exception_from_error_queue` to
    raise an exception wrapped by *error*.
    """
    def openssl_assert(ok):
        pass
    pass


def path_bytes(s: StrOrBytesPath) -> bytes:
    """
    Convert a Python path to a :py:class:`bytes` for the path which can be
    passed into an OpenSSL API accepting a filename.

    :param s: A path (valid for os.fspath).

    :return: An instance of :py:class:`bytes`.
    """
    pass


def byte_string(s: str) -> bytes:
    pass


# A marker object to observe whether some optional arguments are passed any
# value or not.
UNSPECIFIED = object()

_TEXT_WARNING = "str for {0} is no longer accepted, use bytes"


def text_to_bytes_and_warn(label: str, obj: Any) -> Any:
    """
    If ``obj`` is text, emit a warning that it should be bytes instead and try
    to convert it to bytes automatically.

    :param str label: The name of the parameter from which ``obj`` was taken
        (so a developer can easily find the source of the problem and correct
        it).

    :return: If ``obj`` is the text string type, a ``bytes`` object giving the
        UTF-8 encoding of that text is returned.  Otherwise, ``obj`` itself is
        returned.
    """
    pass
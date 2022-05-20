"""
Collection of utility functions for the puresnmp package.
"""
import asyncio
import hashlib
import pkgutil
from dataclasses import dataclass
from functools import lru_cache
from time import time
from types import ModuleType
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
)

from x690.types import ObjectIdentifier

from puresnmp.credentials import V3
from puresnmp.exc import InvalidResponseId, SnmpError
from puresnmp.typevars import TAnyIp
from puresnmp.varbind import VarBind

try:
    from typing import Protocol
except ImportError:
    from typing_extensions import Protocol

T = TypeVar("T", bound=Any)
TTableRow = TypeVar("TTableRow", bound=Any)


class TDigestable(Protocol):
    """
    Typing protocol copied from https://github.com/python/typeshed/blob/569fcea637023b3df2fe45c6f08c26037bfa6a74/stdlib/hashlib.pyi#L5
    """

    digest_size: int
    block_size: int

    # [Python documentation note] Changed in version 3.4: The name attribute has
    # been present in CPython since its inception, but until Python 3.4 was not
    # formally specified, so may not exist on some platforms
    name: str

    def __init__(self, data: bytes = ...) -> None:
        ...

    def copy(self) -> "TDigestable":
        ...

    def digest(self) -> bytes:
        ...

    def hexdigest(self) -> str:
        ...

    def update(self, __data: bytes) -> None:
        ...


@dataclass(frozen=True)
class WalkRow:
    """
    A wrapper around an SNMP Walk item.

    This also keeps track whether this walk result should be considered the
    last row or not.
    """

    #: The value of the "current" row in a walk operation
    value: Any
    #: Whether there are still values following this row
    unfinished: bool


@dataclass(frozen=True)
class BulkResult:
    """
    A representation for results of a "bulk" request.

    These requests get both "non-repeating values" (scalars) and "repeating
    values" (lists). This wrapper makes these terms a bit friendlier to use.
    """

    #: A mapping from object-identifiers to scalar (single) values for those
    #: OIDs
    scalars: Dict[ObjectIdentifier, Any]
    #: A mapping from object-identifiers to "walk" results below those OIDs
    listing: Dict[ObjectIdentifier, Any]


def group_varbinds(
    varbinds: List[VarBind],
    effective_roots: List[ObjectIdentifier],
    user_roots: Optional[List[ObjectIdentifier]] = None,
) -> Dict[ObjectIdentifier, List[VarBind]]:
    """
    Takes a list of varbinds and a list of base OIDs and returns a mapping from
    those base IDs to lists of varbinds.

    Varbinds returned from a walk operation which targets multiple OIDs is
    returned as "interleaved" list. This functions extracts these interleaved
    items into a more usable dictionary.

    >>> from x690.types import Integer
    >>> result = group_varbinds(
    ...     [
    ...         VarBind(ObjectIdentifier("1.1.1"), Integer(1)),
    ...         VarBind(ObjectIdentifier("2.2.2"), Integer(1)),
    ...         VarBind(ObjectIdentifier("1.1.2"), Integer(1)),
    ...         VarBind(ObjectIdentifier("2.2.3"), Integer(1)),
    ...     ],
    ...     [
    ...         ObjectIdentifier("1.1"),
    ...         ObjectIdentifier("2.2"),
    ...     ],
    ... )
    >>> sorted(result.keys())
    [ObjectIdentifier('1.1'), ObjectIdentifier('2.2')]
    >>> result[ObjectIdentifier("1.1")]
    [VarBind(oid=ObjectIdentifier('1.1.1'), value=Integer(1)), VarBind(oid=ObjectIdentifier('1.1.2'), value=Integer(1))]
    >>> result[ObjectIdentifier("2.2")]
    [VarBind(oid=ObjectIdentifier('2.2.2'), value=Integer(1)), VarBind(oid=ObjectIdentifier('2.2.3'), value=Integer(1))]


    :param varbinds: A list of VarBind instances.
    :param effective_roots: The list of OIDs that were requested from the SNMP
        agent.
    :param user_roots: The set of VarBind instances that were requested by the
        user. This is used internally for walk requests. On each request
        following the first, the requested OIDs will differ from the OIDs
        requested by the user. This list will keep track of the original OIDs
        to determine when the walk needs to terminate.
    """
    user_roots = user_roots or []
    n = len(effective_roots)

    results = {}
    for i in range(n):
        results[effective_roots[i]] = varbinds[i::n]

    if user_roots:
        new_results = {}
        for key, value in results.items():
            containment = [base for base in user_roots if key in base]
            if len(containment) > 1:
                raise RuntimeError(
                    "Unexpected OID result. A value was "
                    "contained in more than one base than "
                    "should be possible!"
                )
            if not containment:
                continue
            new_results[containment[0]] = value
            results = new_results

    return results


def get_unfinished_walk_oids(
    grouped_oids: Dict[ObjectIdentifier, List[VarBind]]
) -> List[Tuple[ObjectIdentifier, WalkRow]]:
    """
    Create a list of OIDs which still have subsequent values in a "walk"
    operation

    :param grouped_oids: A dictionary containing VarBinds as values. The keys
        are the base OID of those VarBinds as requested by the user. We need to
        keep track of the base to be able to tell when a walk over OIDs is
        finished (that is, when we hit the first OID outside the base).
    """

    # grouped_oids contains a list of values for each requested OID. We need to
    # determine if we need to continue fetching: Inspect the last item of each
    # list if those OIDs are still children of the requested IDs we need to
    # continue fetching using *those* IDs (as we're using GetNext behaviour).
    # If they are *not* children of the requested OIDs, we went too far (in the
    # case of a bulk operation) and need to remove all outliers.
    #
    # The above behaviour is the same for both bulk and simple operations. For
    # simple operations we simply have a list of 1 element per OID, but the
    # behaviour is identical

    # Build a mapping from the originally requested OID to the last fetched OID
    # from that tree.
    last_received_oids = {
        k: WalkRow(v[-1], v[-1].oid in k) for k, v in grouped_oids.items() if v
    }

    output = [
        item
        for item in sorted(last_received_oids.items())
        if item[1].unfinished
    ]
    return output


def tablify(
    varbinds: Iterable[VarBind],
    num_base_nodes: int = 0,
    base_oid: str = "",
    _rowtype: Type[TTableRow] = Dict[str, Any],  # type: ignore
) -> List[TTableRow]:
    # pylint: disable=line-too-long
    """
    Converts a list of varbinds into a table-like structure. *num_base_nodes*
    can be used for table which row-ids consist of multiple OID tree nodes. By
    default, the last node is considered the row ID, and the second-last is the
    column ID. Example:

    By default, for the table-cell at OID ``1.2.3.4.5``, ``4`` is the column
    index and ``5`` is the row index.

    Using ``num_base_nodes=2`` will only use the first two nodes (``1.2``) as
    table-identifier, so ``3`` becomes the column index, and ``4.5`` becomes
    the row index.

    The output should *not* be considered ordered in any way. If you need it
    sorted, you must sort it after retrieving the table from this function!

    Each element of the output is a dictionary where each key is the column
    index. By default the index ``0`` will be added, representing the row ID.

    Example::

        >>> data = [
        ...     (ObjectIdentifier('1.2.1.1'), 'row 1 col 1'),
        ...     (ObjectIdentifier('1.2.1.2'), 'row 2 col 1'),
        ...     (ObjectIdentifier('1.2.2.1'), 'row 1 col 2'),
        ...     (ObjectIdentifier('1.2.2.2'), 'row 2 col 2'),
        ... ]
        >>> tablify(data)
        [{'0': '1', '1': 'row 1 col 1', '2': 'row 1 col 2'}, {'0': '2', '1': 'row 2 col 1', '2': 'row 2 col 2'}]


    Example with longer row ids (using the *first* two as table identifiers)::

        >>> data = [
        ...     (ObjectIdentifier('1.2.1.5.10'), 'row 5.10 col 1'),
        ...     (ObjectIdentifier('1.2.1.6.10'), 'row 6.10 col 1'),
        ...     (ObjectIdentifier('1.2.2.5.10'), 'row 5.10 col 2'),
        ...     (ObjectIdentifier('1.2.2.6.10'), 'row 6.10 col 2'),
        ... ]
        >>> tablify(data, num_base_nodes=2)
        [{'0': '5.10', '1': 'row 5.10 col 1', '2': 'row 5.10 col 2'}, {'0': '6.10', '1': 'row 6.10 col 1', '2': 'row 6.10 col 2'}]
    """
    # pylint: enable=line-too-long

    if isinstance(base_oid, str) and base_oid:

        base_oid_parsed = ObjectIdentifier(base_oid)
        # Each table has a sub-index for the table "entry" so the number of
        # base-nodes needs to be incremented by 1
        num_base_nodes = len(base_oid_parsed)

    rows: Dict[str, TTableRow] = {}
    for oid, value in varbinds:
        if num_base_nodes:
            tail = oid.nodes[num_base_nodes:]
            col_id_nodes, row_id_nodes = tail[0], tail[1:]
            col_id = str(col_id_nodes)
            row_id = ".".join([str(node) for node in row_id_nodes])
        else:
            col_id = str(oid.nodes[-2])
            row_id = str(oid.nodes[-1])
        tmp: TTableRow = {  # type: ignore
            "0": row_id,
        }
        row = rows.setdefault(row_id, tmp)
        row[str(col_id)] = value
    return list(rows.values())


def password_to_key(
    hash_implementation: Callable[[bytes], TDigestable], padding_length: int
) -> Callable[[bytes, bytes], bytes]:
    """
    Create a helper function to convert passwords to SNMP compliant keys
    according to :rfc:`3414`.

    >>> hasher = password_to_key(hashlib.sha1, 20)
    >>> key = hasher(b"mypasswd", b"target-engine-id")
    >>> key.hex()
    '999ec23ca66b9d3f187ab5208840c30b0450b452'

    :param hash_implementation: A callable that creates an object with a
        ".digest()" method from a bytes-object. Usable examples are
        `hashlib.md5` and `hashlib.sha1`
    :param padding_length: The padding length to be used during hashing (as
        defined in the SNMP rfc)
    :returns: A callable which can be used to derive an SNMP compliant key
        from a password.
    """

    @lru_cache(maxsize=None)
    def hasher(password: bytes, engine_id: bytes) -> bytes:
        """
        Derive a key from a password and engine-id.

        :param password: The user password
        :param engine_id: The target engine ID
        :returns: The derived key
        """
        # Repeat the password for a total of 1MB worth of data (as per SNMP rfc)
        hash_size = 1024 * 1024
        num_words = hash_size // len(password)
        tmp = (password * (num_words + 1))[:hash_size]
        hash_instance = hash_implementation(tmp)
        key = hash_instance.digest()
        localised_buffer = (
            key[:padding_length] + engine_id + key[:padding_length]
        )
        final_key = hash_implementation(localised_buffer).digest()
        return final_key

    hasher.__name__ = f"<hasher:{hash_implementation}>"  # type: ignore
    return hasher


def generate_engine_id_ip(pen: int, ip: TAnyIp) -> bytes:
    """
    Generates a valid SNMP Engine ID using a private enterprise number and an
    ip-address.

    >>> from ipaddress import ip_address
    >>> generate_engine_id_ip(696, ip_address("192.0.2.1"))
    b'\\x80\\x00\\x02\\xb8\\x01\\xc0\\x00\\x02\\x01'

    .. seealso::
        `Engine ID structure <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
            ASN.1 definition for engine-id encoding
        `Engine ID types <https://tools.ietf.org/html/rfc5343#section-4>`_
            List of valid engine-id variants
        `PEN list <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
            List of publicly registered private enterprise numbers
    """
    buffer = bytearray(pen.to_bytes(4, "big"))
    # Setting the first bit to 1 is the same as setting the first byte to 16*8
    buffer[0] = 16 * 8
    fmt = 1 if ip.version == 4 else 2
    buffer.append(fmt)
    buffer.extend(ip.packed)
    return bytes(buffer)


def generate_engine_id_mac(pen: int, mac_address: str) -> bytes:
    """
    Generates a valid SNMP Engine ID using a private enterprise number and a
    mac-address.

    >>> generate_engine_id_mac(696, "01:02:03:04:05:06")
    b'\\x80\\x00\\x02\\xb8\\x03\\x01\\x02\\x03\\x04\\x05\\x06'

    .. seealso::
        `Engine ID structure <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
            ASN.1 definition for engine-id encoding
        `Engine ID types <https://tools.ietf.org/html/rfc5343#section-4>`_
            List of valid engine-id variants
        `PEN list <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
            List of publicly registered private enterprise numbers
    """
    buffer = bytearray(pen.to_bytes(4, "big"))

    # Setting the first bit to 1 is the same as setting the first byte to 16*8
    buffer[0] = 16 * 8

    if "-" in mac_address:
        octets = [int(oct, 16) for oct in mac_address.split("-")]
    else:
        octets = [int(oct, 16) for oct in mac_address.split(":")]

    buffer.append(3)
    buffer.extend(octets)
    return bytes(buffer)


def generate_engine_id_text(pen: int, text: str) -> bytes:
    """
    Generates a valid SNMP Engine ID using a private enterprise number and a
    custom text (no longer than 27 characters).

    >>> generate_engine_id_text(696, "hello")
    b'\\x80\\x00\\x02\\xb8\\x04hello'

    .. seealso::
        `Engine ID structure <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
            ASN.1 definition for engine-id encoding
        `Engine ID types <https://tools.ietf.org/html/rfc5343#section-4>`_
            List of valid engine-id variants
        `PEN list <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
            List of publicly registered private enterprise numbers
    """
    if len(text) > 27:
        raise SnmpError(
            "Invalid engine ID. Text must have fewer than 27 characters"
        )
    buffer = bytearray(pen.to_bytes(4, "big"))
    # Setting the first bit to 1 is the same as setting the first byte to 16*8
    buffer[0] = 16 * 8
    buffer.append(4)
    buffer.extend(text.encode("ascii"))
    return bytes(buffer)


def generate_engine_id_octets(pen: int, octets: bytes) -> bytes:
    """
    Generates a valid SNMP Engine ID using a private enterprise number and a
    custom byte-string (no longer than 27 bytes)

    >>> generate_engine_id_octets(696, b"hello")
    b'\\x80\\x00\\x02\\xb8\\x05hello'

    .. seealso::
        `Engine ID structure <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
            ASN.1 definition for engine-id encoding
        `Engine ID types <https://tools.ietf.org/html/rfc5343#section-4>`_
            List of valid engine-id variants
        `PEN list <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers>`_
            List of publicly registered private enterprise numbers
    """
    if len(octets) > 27:
        raise SnmpError(
            f"Invalid engine ID. The value {octets!r} is longer than 27 octets"
        )
    buffer = bytearray(pen.to_bytes(4, "big"))
    # Setting the first bit to 1 is the same as setting the first byte to 16*8
    buffer[0] = 16 * 8
    buffer.append(5)
    buffer.extend(octets)
    return bytes(buffer)


def validate_response_id(request_id: int, response_id: int) -> None:
    """
    Compare request and response IDs and raise an appropriate error.

    Raises an appropriate error if the IDs differ. Otherwise returns

    This helper method ensures we're always returning the same exception type
    on invalid response IDs.
    """
    if response_id != request_id:
        raise InvalidResponseId(
            f"Invalid response ID {response_id} for request id {request_id}"
        )


def iter_namespace(
    ns_pkg: ModuleType,
) -> Generator[pkgutil.ModuleInfo, None, None]:
    """
    Iterates over modules inside the given namespace
    """
    # Specifying the second argument (prefix) to iter_modules makes the
    # returned name an absolute name instead of a relative one. This allows
    # import_module to work without having to do additional modification to
    # the name.
    return pkgutil.iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")  # type: ignore


def localise_key(credentials: V3, engine_id: bytes) -> bytes:
    """
    Derive a localised key from the user-credentials.

    This follows the logic as dictated by :rfc:`3414` melding the recipient
    engine-id with the user-credentials into a kay used for de-/en-cryption
    of packets.

    .. seealso: https://tools.ietf.org/html/rfc3414#section-2.6

    >>> from puresnmp.credentials import V3, Auth, Priv
    >>> engine_id = b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02"
    >>> localised = localise_key(
    ...     V3(b"user", Auth(b"maplesyrup", "md5"), Priv(b"privkey", "des")),
    ...     engine_id
    ... )
    >>> localised.hex()
    '4924c679907476d038b258097995a15c'
    """
    if credentials.priv is None:
        raise SnmpError(
            "Attempting to derive a localised key from an empty "
            "privacy object!"
        )
    if credentials.auth is None:
        raise SnmpError(
            "Attempting to derive a localised key from an empty " "auth object!"
        )
    if credentials.auth.method == "md5":
        hasher = password_to_key(hashlib.md5, 16)
    elif credentials.auth.method == "sha1":
        hasher = password_to_key(hashlib.sha1, 20)
    else:
        raise SnmpError(
            "Unknown authentication method: %r" % credentials.auth.method
        )

    output = hasher(credentials.priv.key, engine_id)
    return output


def get_request_id() -> int:  # pragma: no cover
    """
    Generates a SNMP request ID.

    This returns a simple integer used to validate if a given response
    matches with the given request.
    """
    return int(time())


def sync(coro: Awaitable[T]) -> T:
    """
    Execute an asyncio corouting in the current event-loop and return the result

    >>> async def foo():
    ...     return "hello"
    >>> sync(foo())
    'hello'

    .. warning::

        This is intended for debugging and testing. If possible you should
        use your own async environment.
    """
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(coro)
    return result

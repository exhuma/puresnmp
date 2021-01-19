"""
Colleciton of utility functions for the puresnmp package.
"""
import pkgutil
from dataclasses import dataclass
from functools import lru_cache
from types import ModuleType
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    Union,
)

from x690.types import ObjectIdentifier

from puresnmp.exc import InvalidResponseId, SnmpError
from puresnmp.snmp import VarBind
from puresnmp.typevars import TAnyIp


@dataclass
class WalkRow:
    """
    A wrapper around an SNMP Walk item.

    This also keeps track whether this walk result should be considered the
    last row or not.
    """

    value: Any
    unfinished: bool


@dataclass
class BulkResult:
    """
    A representation for results of a "bulk" request.

    These requests get both "non-repeating values" (scalars) and "repeating
    values" (lists). This wrapper makes these terms a bit friendlier to use.
    """

    scalars: Dict[str, Any]
    listing: Dict[str, Any]


def group_varbinds(varbinds, effective_roots, user_roots=None):
    # type: (List[VarBind], List[ObjectIdentifier], Optional[List[ObjectIdentifier]]) -> Dict[ObjectIdentifier, List[VarBind]]
    """
    Takes a list of varbinds and a list of base OIDs and returns a mapping from
    those base IDs to lists of varbinds.

    Varbinds returned from a walk operation which targets multiple OIDs is
    returned as "interleaved" list. This functions extracts these interleaved
    items into a more usable dictionary.

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


def get_unfinished_walk_oids(grouped_oids):
    # type: (Dict[ObjectIdentifier, List[VarBind]]) -> List[Tuple[ObjectIdentifier, WalkRow]]
    """
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


def tablify(varbinds, num_base_nodes=0, base_oid=""):
    # type: ( Iterable[Union[VarBind, Tuple[Any, Any]]], int, str ) -> List[Dict[str, Any]]
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

    if isinstance(base_oid, str) and base_oid:

        base_oid_parsed = ObjectIdentifier(base_oid)
        # Each table has a sub-index for the table "entry" so the number of
        # base-nodes needs to be incremented by 1
        num_base_nodes = len(base_oid_parsed)

    rows = {}  # type: Dict[str, Dict[str, Type[Any]]]
    for oid, value in varbinds:
        if num_base_nodes:
            tail = oid.nodes[num_base_nodes:]
            col_id, row_id = tail[0], tail[1:]
            row_id = ".".join([str(node) for node in row_id])
        else:
            col_id = str(oid.nodes[-2])
            row_id = str(oid.nodes[-1])
        tmp = {
            "0": row_id,
        }
        row = rows.setdefault(row_id, tmp)  # type: ignore
        row[str(col_id)] = value  # type: ignore
    return list(rows.values())


def password_to_key(
    hash_implementation: Callable[..., Any], padding_length: int
) -> Callable[[bytes, bytes], bytes]:
    @lru_cache(maxsize=None)
    def hasher(password: bytes, engine_id: bytes) -> bytes:
        hash_instance = hash_implementation()
        # Hash 1MB worth of data
        hash_size = 1024 * 1024
        num_words = hash_size // len(password)
        tmp = (password * (num_words + 1))[:hash_size]
        hash_instance.update(tmp)
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
        `PEN list <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers`_
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
        `PEN list <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers`_
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
        `PEN list <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers`_
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
        `PEN list <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers`_
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

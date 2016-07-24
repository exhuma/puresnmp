from .types import (
    Integer,
    List,
    Oid,
    String,
)


class Version:
    V2C = 0x01
    V1 = 0x00


class Pdu:
    GET_REQUEST = 0xa0
    GET_RESPONSE = 0xa2


def decode_first_byte(char):
    """
    Decodes first byte of an OID.
    """
    if char < 1000:
        if 0 <= char < 40:
            first_node = '0'
            second_node = str(char)
        elif 40 <= char < 80:
            first_node = '1'
            second_node = str(char - 40)
        elif char >= 80:
            first_node = '2'
            second_node = str(char - 80)
        return first_node, second_node
    else:
        raise ValueError('Unexpected start byte for an OID (%x >= %x!' % (
            char, 1000))


def decode_large_value(current_char, stream):
    """
    If we encounter a value larger than 127, we have to consume from the stram
    until we encounter a value below 127 and recombine them.

    See: https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
    """
    buffer = []
    while current_char > 127:
        buffer.append(current_char ^ 0b10000000)
        current_char = next(stream)
    total = current_char
    for i, digit in enumerate(reversed(buffer)):
        total += digit * 128**(i+1)
    return total


def consume(data):
    variable_type = data[0]
    size = data[1]
    value = data[2:2+size]
    if variable_type == Integer.HEADER:
        value = int.from_bytes(value, byteorder="big")
    elif variable_type == String.HEADER:
        value = value.decode('ascii')
    elif variable_type == Oid.HEADER:
        tmp = []
        iterator = iter(value)
        for char in iterator:
            # See also the function "decode_first_byte". It's more complicated
            # than this for other values than "1.3"
            if char == 0x2b:
                tmp.extend(['1', '3'])
                continue

            # Each node can only contain values from 0-127. Other values need to
            # be combined.
            if char > 127:
                total = decode_large_value(char, iterator)
                tmp.extend([str(total)])
                continue
            tmp.append(str(char))
        value = '.'.join(tmp)
    else:
        raise ValueError('Unknown variable type: %s' % hex(variable_type))
    return data[2+size:], variable_type, value


def unmarshal(data):
    remaining = data[:]
    header, pdu_size, remaining = remaining[0], remaining[1], remaining[2:]
    if header != 0x30:
        raise ValueError('Excpected ASN.1 Header (0x30) but got %s' % hex(
            header))

    if len(remaining) != pdu_size:
        raise ValueError('Corrupt PDU. Size mismatch: '
                         'expected (header)=%d, actual size=%d' % (
                             pdu_size, len(remaining)))

    remaining, _, version = consume(remaining)
    remaining, _, community = consume(remaining)
    request_type, request_length = remaining[0], remaining[1]
    remaining = remaining[2:]  # drop the next header

    if len(remaining) != request_length:
        raise ValueError('Corrupt PDU. Size mismatch: '
                         'expected (header)=%d, actual size=%d' % (
                             request_length, len(remaining)))

    remaining, _, request_id = consume(remaining)
    remaining, _, error_code = consume(remaining)
    remaining, _, error_index = consume(remaining)
    remaining = remaining[4:]  # drop the next two "list" headers
    remaining, _, request_oid = consume(remaining)
    remaining, response_type, response_value = consume(remaining)

    if remaining:
        raise ValueError('Junk data at end of packet: %r' % remaining)

    return {
        'version': data[4],
        'community': community,
        'pdu_type': request_type,
        'request_id': request_id,
        'error_code': error_code,
        'error_index': error_index,
        'value': response_value,
        'value_type': response_type,
    }


def marshal(data):
    version = bytes([Integer.HEADER, 1, data['version']])
    community = bytes(String(data['community']))
    output = bytes([
        0x30,  # ASN.1 Header
        0x29,  # PDU length
    ]) + version + community + bytes([
        0xa0, 0x1c,  # PDU Type
        0x02, 0x04, 0x72, 0x0b, 0x8c, 0x3f,  # Request ID
        0x02, 0x01, 0x00,  # Error Type
        0x02, 0x01, 0x00,  # Error Index
        0x30,  # Variable Type (List)
        0x0e,  # Length
        0x30,  # Variable Type (List)
        0x0c,  # Length
        0x06,  # Variable Type (OID)
        0x08,  # Length
        0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00,  # Value
        0x05, 0x00,  # NULL (end of list)
    ])
    return output

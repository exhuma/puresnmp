from binascii import hexlify, unhexlify


class Length:
    INDEFINITE = "indefinite"


def encode_length(value):
    """
    The "length" field must be specially encoded for values above 127.
    Additionally, from X.690:

        8.1.3.2 A sender shall:

            a) use the definite form (see 8.1.3.3) if the encoding is primitive;
            b) use either the definite form (see 8.1.3.3) or the indefinite form
               (see 8.1.3.6), a sender's option, if the encoding is constructed
               and all immediately available;
            c) use the indefinite form (see 8.1.3.6) if the encoding is
               constructed and is not all immediately available.

    See also: https://en.wikipedia.org/wiki/X.690#Length_octets
    """
    if value == Length.INDEFINITE:
        return bytes([0b10000000])

    if value < 127:
        return bytes([value])

    output = []
    while value > 0:
        value, remainder = value // 256, value % 256
        output.append(remainder)

    # prefix length information
    output = [0b10000000 | len(output)] + output
    return bytes(output)


def consume_length(data):
    if data[0] == 0b11111111:
        # reserved
        raise NotImplementedError('This is a reserved case in X690')
    elif data[0] & 0b10000000 == 0:
        # definite short form
        output = int.from_bytes([data[0]], 'big')
        data = data[1:]
    elif data[0] ^ 0b10000000 == 0:
        # indefinite form
        raise NotImplementedError('Indefinite lenghts are not yet implemented!')
    else:
        # definite long form
        num_octets = int.from_bytes([data[0] ^ 0b10000000], 'big')
        value_octets = data[1:1+num_octets]
        output = int.from_bytes(value_octets, 'big')
        data = data[num_octets + 1:]
    return output, data


def visible_octets(data: bytes) -> str:
    """
    Returns a geek-friendly output of a bytes object.
    """
    hexed = hexlify(data).decode('ascii')
    tuples = [''.join((a, b)) for a, b in zip(hexed[::2], hexed[1::2])]
    line = []
    output = []
    ascii = []
    for idx, octet in enumerate(tuples):
        line.append(octet)
        # only use printable characters in ascii output
        ascii.append(octet if 32 <= int(octet, 16) < 127 else '2e')
        if (idx+1) % 8 == 0:
            line.append('')
        if (idx+1) % 8 == 0 and (idx+1) % 16 == 0:
            raw_ascii = unhexlify(''.join(ascii))
            raw_ascii = raw_ascii.replace(b'\\n z', b'.')
            ascii = []
            output.append('%-50s %s' % (' '.join(line),
                                        raw_ascii.decode('ascii')))
            line = []
    raw_ascii = unhexlify(''.join(ascii))
    raw_ascii = raw_ascii.replace(b'\\n z', b'.')
    output.append('%-50s %s' % (' '.join(line), raw_ascii.decode('ascii')))
    line = []
    return '\n'.join(output)

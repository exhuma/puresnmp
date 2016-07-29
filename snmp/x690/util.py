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

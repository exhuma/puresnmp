def encode_length(value):
    """
    The "length" field must be specially encoded for values above 127.

    See https://en.wikipedia.org/wiki/X.690#Length_octets
    """
    if value & 0b10000000:
        raise NotImplementedError('Length values above 127 are not yet '
                                  'implemented!')
    return value


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

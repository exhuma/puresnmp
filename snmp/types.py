NULL = b'\x05\x00'


class Type:

    @staticmethod
    def from_bytes(data):
        raise NotImplementedError('Not yet implemented')

    def __bytes__(self):
        raise NotImplementedError('Not yet implemented')


class String(Type):

    HEADER = 0x04

    def __init__(self, value):
        self.value = value
        self.length = len(value)

    def __bytes__(self):
        return (bytes([String.HEADER, self.length]) +
                self.value.encode('ascii'))


class List(Type):

    HEADER = 0x30

    def __init__(self, *items):
        self.items = items

    def __bytes__(self):
        output = [bytes(item) for item in self.items]
        output = b''.join(output)
        length = len(output)
        return bytes([List.HEADER, length]) + output + NULL


class Integer:
    HEADER = 0x02

    @staticmethod
    def from_bytes(data):
        if data[0] != Integer.HEADER:
            raise ValueError('Invalid type header! Expected 0x02, got 0x%02x' %
                             data[0])
        if data[1] != 1:
            raise NotImplementedError("Integers with a byte-length bigger than "
                                      "one have so far been never encountered. "
                                      "Haven't looked into their decoding yet")
        return Integer(data[2])

    def __init__(self, value):
        self.value = value

    def __bytes__(self):
        return bytes([self.HEADER, 0x01] + [self.value])

    def __eq__(self, other):
        return type(self) == type(other) and self.value == other.value

    def __repr__(self):
        return 'Integer(%r)' % self.value


class Oid(Type):

    HEADER = 0x06

    def __init__(self, *identifiers):
        # The first two bytes are collapsed according to X.690
        # See https://en.wikipedia.org/wiki/X.690#BER_encoding
        first, second, rest = identifiers[0], identifiers[1], identifiers[2:]
        first_output = (40*first) + second

        self.identifiers = [first_output] + list(rest)
        self.length = len(self.identifiers)

    def __bytes__(self):
        return bytes([self.HEADER, self.length] + self.identifiers)

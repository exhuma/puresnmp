NULL = b'\x05\x00'


class Type:

    @staticmethod
    def from_bytes(data):
        raise NotImplementedError('Not yet implemented')

    def __bytes__(self):
        raise NotImplementedError('Not yet implemented')


class String(Type):

    HEADER = 0x04

    @staticmethod
    def from_bytes(data):
        if data[0] != String.HEADER:
            raise ValueError('Invalid type header! Expected 0x04, got 0x%02x' %
                             data[0])
        raw_content = data[2:2+data[1]]
        return String(raw_content.decode('ascii'))

    def __init__(self, value):
        self.value = value
        self.length = len(value)

    def __bytes__(self):
        return (bytes([String.HEADER, self.length]) +
                self.value.encode('ascii'))

    def __repr__(self):
        return 'String(%r)' % self.value

    def __eq__(self, other):
        return type(self) == type(other) and self.value == other.value


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

    @staticmethod
    def decode_large_value(current_char, stream):
        """
        If we encounter a value larger than 127, we have to consume from the
        stram until we encounter a value below 127 and recombine them.

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

    @staticmethod
    def from_bytes(data):
        if data[0] != Oid.HEADER:
            raise ValueError('Invalid type header! Expected 0x02, got 0x%02x' %
                             data[0])

        identifiers = data[2:2+data[1]]
        # unpack the first byte into first and second sub-identifiers.
        first, second = identifiers[0] // 40, identifiers[0] % 40
        output = [first, second]

        remaining = iter(identifiers[1:])

        for char in remaining:
            # Each node can only contain values from 0-127. Other values need to
            # be combined.
            if char > 127:
                collapsed_value = Oid.decode_large_value(char, remaining)
                output.append(collapsed_value)
                continue
            output.append(char)

        return Oid(*output)

    def __init__(self, *identifiers):
        # If the user hands in an iterable, instead of positional arguments,
        # make sure we unpack it
        if len(identifiers) == 1 and not isinstance(identifiers[0], int):
            identifiers = identifiers[0]

        # The first two bytes are collapsed according to X.690
        # See https://en.wikipedia.org/wiki/X.690#BER_encoding
        first, second, rest = identifiers[0], identifiers[1], identifiers[2:]
        first_output = (40*first) + second

        self.identifiers = identifiers
        self.__collapsed_identifiers = [first_output] + list(rest)
        self.length = len(self.__collapsed_identifiers)

    def __bytes__(self):
        return bytes([self.HEADER, self.length] + self.__collapsed_identifiers)

    def __repr__(self):
        return 'Oid(%r)' % (self.identifiers, )

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.__collapsed_identifiers == other.__collapsed_identifiers)

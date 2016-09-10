Development Tips
================

Determining Type Bytes
----------------------

The single byte for type information packs 3 distinct values:

* The "class" (primitive, universal or context)
* Whether it's a primitive or constructed value
* The actual type ID

This can make it difficult to read network captures (or hex dumps in the
test-data folder) as you only see the packed value. Sometimes you might be
interested in the 3 separate values though.

In that case, the best place to debug is the
:py:func:`puresnmp.x690.types.pop_tlv` function as it contains both, the raw
byte value and the parsed :py:class:`puresnmp.x690.util.TypeInfo` instance.


Testing Bytes for Equality
--------------------------

To get a bit more helpful output when compariing bytes a custom assertion
method is implemented in the ByteTester class. The method is called
py:meth:`puresnmp.test.ByteTester.assertBytesEqual` and will list a couple of
helpful columns, comparing each byte.


Displaying Bytes
----------------

Sometimes it's helpful to display bytes on screen. By default using ``print``
is not really helpful, nor readable.For this reason a "hexdump" like output has
been implemented in :py:func:`puresnmp.x690.visible_octets`.

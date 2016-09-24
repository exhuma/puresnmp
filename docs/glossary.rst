Glossary
========

.. glossary::

    X.690
        X.690 defines the encoding rules for ASN.1 notation. It is the
        underlying standard used by SNMP. It's reference document can be found
        here: https://www.itu.int/rec/T-REC-X.690/en

        Apart from encoding rules, it also defines a set of core variable types
        like :py:class:`~puresnmp.x690.types.ObjectIdentifier`,
        :py:class:`~puresnmp.x690.types.Integer`).

    TLV
        Type Length Value (See
        https://en.wikipedia.org/wiki/Type-length-value)

    PDU
        A Protocol Data Unit. A logical packet exchanged between client and
        server.

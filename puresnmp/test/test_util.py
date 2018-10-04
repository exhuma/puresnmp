from puresnmp.pdu import VarBind
from puresnmp.util import WalkRow, get_unfinished_walk_oids, group_varbinds
from puresnmp.x690.types import Null, ObjectIdentifier

OID = ObjectIdentifier.from_string


def test_group_varbinds():
    '''
    "group_varbinds" should convert an interleaved list of OIDs into a more
    usable dictionary.
    '''
    varbinds = [
        VarBind(OID('1.1.1'), Null()),
        VarBind(OID('2.2.1'), Null()),
        VarBind(OID('3.3.1'), Null()),
        VarBind(OID('1.1.2'), Null()),
        VarBind(OID('2.2.2'), Null()),
        VarBind(OID('3.3.2'), Null()),
        VarBind(OID('1.1.3'), Null()),
        VarBind(OID('2.2.3'), Null()),
        VarBind(OID('3.3.3'), Null()),
    ]
    effective_roots = [
        OID('1.1'),
        OID('2.2'),
        OID('3.3'),
    ]
    result = group_varbinds(varbinds, effective_roots)
    expected = {
        OID('1.1'): [
            VarBind(OID('1.1.1'), Null()),
            VarBind(OID('1.1.2'), Null()),
            VarBind(OID('1.1.3'), Null()),
        ],
        OID('2.2'): [
            VarBind(OID('2.2.1'), Null()),
            VarBind(OID('2.2.2'), Null()),
            VarBind(OID('2.2.3'), Null()),
        ],
        OID('3.3'): [
            VarBind(OID('3.3.1'), Null()),
            VarBind(OID('3.3.2'), Null()),
            VarBind(OID('3.3.3'), Null()),
        ],
    }

    assert result == expected


def test_get_unfinished_walk_oids():
    oid_groups = {
        OID('1.1'): [
            VarBind(OID('1.1.1'), Null()),
            VarBind(OID('1.1.2'), Null()),
        ],
        OID('2.2'): [
            VarBind(OID('2.2.1'), Null()),
            VarBind(OID('2.2.2'), Null()),
        ],
        OID('3.3'): [
            VarBind(OID('3.3.1'), Null()),
            VarBind(OID('3.4.2'), Null()),
        ]
    }
    result = get_unfinished_walk_oids(oid_groups)
    expected = [
        (OID('1.1'), WalkRow(VarBind(OID('1.1.2'), Null()), unfinished=True)),
        (OID('2.2'), WalkRow(VarBind(OID('2.2.2'), Null()), unfinished=True)),
    ]
    assert result == expected

from typing import Any, NamedTuple, Optional

from x690.types import Null, ObjectIdentifier, Type


class VarBind(NamedTuple):
    """
    A "VarBind" is a 2-tuple containing an object-identifier and the
    corresponding value.
    """

    oid: ObjectIdentifier = ObjectIdentifier()
    value: Type[Any] = Null()


class PyVarBind(NamedTuple):
    """
    A "PyVarBind" is a 2-tuple containing an object-identifier and the
    corresponding value using native Python data-types
    """

    oid: str = ""
    value: Optional[Any] = None

    @staticmethod
    def from_raw(raw_varbind: VarBind) -> "PyVarBind":
        return PyVarBind(
            raw_varbind.oid.pythonize(), raw_varbind.value.pythonize()
        )

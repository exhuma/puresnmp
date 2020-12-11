# pylint: skip-file
import sys
from os.path import dirname

from hexlib import readbytes_multiple
from x690.types import OctetString, Sequence, pop_tlv

import puresnmp.types
from puresnmp.messageprocessing import V3Flags

HERE = dirname(__file__)


def process_packet_v3(v3: Sequence) -> None:
    from puresnmp.messageprocessing import prepare_data_elements

    res = prepare_data_elements(
        transport_domain=None,
        transport_address=None,
        whole_msg=bytes(v3),
        whole_msg_length=len(bytes(v3)),
    )
    print(res)


def process_packet(envelope: Sequence) -> None:
    version = envelope[0].pythonize()
    if version == 3:
        process_packet_v3(envelope)


def main():
    from puresnmp.messageprocessing import prepare_data_elements

    blobs = list(readbytes_multiple("packet-noauth-nopriv.hex", HERE))
    for blob in blobs[2:]:
        res = prepare_data_elements(
            transport_domain=None,
            transport_address=None,
            whole_msg=blob,
        )
        print(res)


def send():
    import puresnmp.engine as e
    from puresnmp.messageprocessing import SNMPV3_MPM
    from puresnmp.pdu import GetRequest
    from puresnmp.security import UserSecurityModel

    d = e.Dispatcher()
    usm = UserSecurityModel()
    usm.local_config["users"] = {
        "helloworld": {
            "authproto": "MD5",
            "privproto": "DES",
            "authkey": "theauthpass",
            "privkey": "privpass",
        }
    }
    d.send_pdu(
        e.TransportDomain.UDPIPV4,
        "127.0.0.1:50009",
        SNMPV3_MPM(),
        usm,
        security_name="foobar",
        security_level=V3Flags(True, False, False),
        context_engine_id=OctetString(b"c0ffee"),
        context_name=OctetString(b"puresnmp-dev"),
        pdu_version=2,
        pdu=GetRequest(1234, "1.3.6.1.2.1.1.2.0"),
        expect_response=True,
    )


def decode_message():
    """
    Try to extrace a "Message" construct from a bytes object
    """
    blobs = list(readbytes_multiple("packet-noauth-nopriv.hex", HERE))
    data = blobs[0]
    from puresnmp.messageprocessing import Message

    result = Message.decode(data)
    print(result)


def display():
    filename = sys.argv[1]
    blobs = list(readbytes_multiple(filename, HERE))
    for blob in blobs:
        try:
            result = Message.decode(blob)
        except:
            result, _ = pop_tlv(blob)
        print("=" * 80)
        print(result.pretty())


if __name__ == "__main__":
    # send()
    # decode_message()
    display()

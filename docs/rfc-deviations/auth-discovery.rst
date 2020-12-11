Auth Discovery Packet
=====================

As per :rfc:`3414` the authentication discovery and privacy discovery are two
separate steps. One for only authentication and one for privacy. They can be
both combined into one packet. ``puresnmp`` will only send the one packet.
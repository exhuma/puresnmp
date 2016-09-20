.. _contributing:

Contributing
============

The package is managed on github_ and all feature-requests, bug-reports and
pull-request should come through there.


Who can contribute and what?
----------------------------

Users
~~~~~

You don't know how to code, but just want to use the library? The library
really needs some first hands-on testing. Questions this will answer:

* Is the documentation helpful (is it easy to get started)?
* Is the library easy to install?
* Do the exposed functions in the high-level API have all the required
  arguments?
* Is the output of the high-level functions sensible and usable?
* Does the lower-level library provide a way to execute advanced commands that
  are not foreseen in the high-level API?


Developers
~~~~~~~~~~

No matter if you're an experienced or advanced developer, any contribution is
welcome. I will try to flag any issues that are coming up as "beginner" or
"advanced". This goes for both "TODO" items in the code and Github Issues.


What can you contribute?
------------------------

TODO hunting
~~~~~~~~~~~~

The project still contains a lot of "TODO" items in the source code. You can
have a look for them by simply grepping for ``TODO`` across the project.


Additional Features
~~~~~~~~~~~~~~~~~~~

Some features are still blatantly missing in the high-level API:

* Bulk requests
* SNMPv3


Auditing (Security, Implementation & Performance)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Is everything I do with SNMP correct? Is my handling of the bytes sent and
  read from the network compliant with the SNMP standard?
* Any security concerns (really no my domain of expertise)?
* Are there performance gains to be gained somewhere?


Tests
~~~~~

While I have access to a large list of devices, it is always best to have it
tested across as many devices as possible. This should include all the
available commands. A clear procedure for this has not yet been defined, but
any information I can get, helps.


Documentation
~~~~~~~~~~~~~

While documentation is currently non-existing, it is one of the next steps on
my roadmap (starting with this document right here). As there is no starting
material yet, there is not much to contribute. But as always, any help is
welcome.

Python 2 Support?
~~~~~~~~~~~~~~~~~

The library is currently deliberately targeted for Python 3. The reason is that
asyncio support in Python 3 may be an interesting subject to check out in the
future.

But Python 2 still exists and may need support. This is not on my highest
priority however.



.. _github: https://www.github.com/exhuma/puresnmp

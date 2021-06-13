.. _contributing:

Contributing
============

The package is managed on github_ and all feature-requests, bug-reports and
pull-request should come through there.


Pull Requests
-------------

When opening a pull request for **bug-fixes or minor improvments**, make sure
to use ``master`` as reference branch. This will always reflect the currently
published version of ``puresnmp``. Alternatively you can use a version-tag as
base.

For new features you should consider using the branch ``develop`` as base.
Anything opened against ``develop`` will usually take a longer time to release.

If unsure whether to use ``develop`` or ``master``, pick anyone of the two and
drop a comment in the PR and I will have a look which one makes more sense.


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

* SNMPv3


Auditing (Security, Implementation & Performance)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Is everything I do with SNMP correct? Is my handling of the bytes sent and
  read from the network compliant with the SNMP standard?
* Any security concerns (really not my domain of expertise)?
* Are there performance gains to be gained somewhere?


Tests
~~~~~

While I have access to a large list of devices, it is always best to have it
tested across as many devices as possible. This should include all the
available commands. A clear procedure for this has not yet been defined, but
any information I can get, helps.


Code Style
----------

As a Python project, the code should conform to PEP8_. To verify you should run
pylint_ over your code. The project contains a local ``pylintrc`` with
customised project settings.

As always, PEP8 is a *guideline* and you are free to add ``# pylint: disable
...`` comments wherever it makes sense to get a clean ``pylint`` output.


.. _PEP8: https://www.python.org/dev/peps/pep-0008/
.. _pylint: https://www.pylint.org/
.. _github: https://www.github.com/exhuma/puresnmp

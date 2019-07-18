.. >>> Shields >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

.. image:: https://travis-ci.org/exhuma/puresnmp.svg?branch=develop
    :target: https://travis-ci.org/exhuma/puresnmp

.. image:: https://readthedocs.org/projects/puresnmp/badge/?version=latest
    :target: http://puresnmp.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

.. image:: https://img.shields.io/badge/repository-github-green.svg?style=flat
    :target: https://github.com/exhuma/puresnmp
    :alt: Github Project

.. image:: https://img.shields.io/pypi/v/puresnmp.svg
    :alt: PyPI
    :target: https://pypi.org/project/puresnmp/

.. <<< Shields <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

----


TL;DR
-----

Jump right in with the `cookbook`_

----


Quick Info
----------

What
    A pure Python implementation for Python 3.3+ of SNMP without any external
    dependencies (neither MIBs or libsnmp).

Why
    SNMP in itself is simple and well defined. A bit convoluted, but simple.
    MIB parsing however complicates the code-base and is *technically* not
    required. They add typing information and variables and give names to OIDs.
    All existing libraries have a direct or indirect dependency on libsnmp.
    With all the advantages and disadvantages.

    The aim of this project is to focus on SNMP in itself and provide a very
    simple API. Instead of implementing ASN.1 parsing, the SNMP related ASN.1
    and X.690 information is hard-coded (keeping in mind that all that's
    hard-coded is well defined).

    It is of course possible to *wrap* this package in another package adding
    MIB parsing and processing. This is, and will be however **out of the scope
    of this project**!

When
    First commit: Sat Jul 23 12:01:05 2016 +0200

Who
    Michel Albert


Installation
------------

::

    pip install puresnmp



Package Version Numbers
-----------------------

As an important side-note, you might want to know that this project follows
`Semantic Versioning`_.

Examples
--------

See the `cookbook`_.

.. _cookbook: http://puresnmp.readthedocs.io/en/latest/cookbook/index.html
.. _Semantic Versioning: http://semver.org/spec/v2.0.0.html

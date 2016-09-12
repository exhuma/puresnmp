from setuptools import setup, find_packages

VERSION = open('puresnmp/version.txt').read().strip()

setup(
    name="puresnmp",
    version=VERSION,
    description="Pure Python SNMP implementation",
    long_description=open("README.rst").read(),
    author="Michel Albert",
    author_email="michel@albert.lu",
    license="BSD",
    include_package_data=True,
    install_requires=[
        'typing',
    ],
    extras_require={
        'dev': [],
        'test': ['pytest-xdist', 'pytest']
    },
    packages=find_packages(exclude=["tests.*", "tests"]),
)

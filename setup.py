from sys import version_info

from setuptools import find_packages, setup

VERSION = open('puresnmp/version.txt').read().strip()
DEPENDENCIES = []
if version_info < (3, 0):
    DEPENDENCIES.append('typing')

setup(
    name="puresnmp",
    version=VERSION,
    description="Pure Python SNMP implementation",
    long_description=open("README.rst").read(),
    author="Michel Albert",
    author_email="michel@albert.lu",
    provides=['puresnmp'],
    license="MIT",
    include_package_data=True,
    install_requires=DEPENDENCIES,
    extras_require={
        'dev': [],
        'test': ['pytest-xdist', 'pytest', 'pytest-coverage']
    },
    packages=find_packages(exclude=["tests.*", "tests", "docs"]),
    url="https://github.com/exhuma/puresnmp",
    keywords="networking snmp",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: System :: Systems Administration',
    ]
)

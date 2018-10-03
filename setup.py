from sys import version_info

from setuptools import find_packages, setup


def get_version():
    # type: () -> str
    '''
    Retrieves the version information for this package.
    '''
    filename = 'puresnmp/version.py'

    with open(filename) as fptr:
        # pylint: disable=invalid-name, exec-used
        obj = compile(fptr.read(), filename, 'single')
        data = {}  # type: ignore
        exec(obj, data)
    return data['VERSION']


VERSION = get_version()
DEPENDENCIES = [
    'verlib',
    'six',
]
if version_info < (3, 5):
    DEPENDENCIES.append('typing')
if version_info < (3, 3):
    DEPENDENCIES.append('ipaddress')
    DEPENDENCIES.append('mock')

TEST_DEPENDENCIES = [
    'pytest-xdist',
    'pytest',
    'pytest-coverage'
]
if version_info >= (3, 6):
    TEST_DEPENDENCIES.append('pytest-asyncio')

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
    package_data={
        'puresnmp': ['py.typed']
    },
    install_requires=DEPENDENCIES,
    extras_require={
        'dev': [],
        'test': TEST_DEPENDENCIES
    },
    packages=find_packages(exclude=["tests.*", "tests", "docs"]),
    url="https://github.com/exhuma/puresnmp",
    keywords="networking snmp",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: System :: Systems Administration',
    ]
)

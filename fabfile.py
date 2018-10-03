import fabric.api as fab


def generate_type_hierarchy():
    """
    Generate a document containing the available variable types.
    """
    fab.local('./env/bin/python -m puresnmp.types > docs/typetree.rst')


@fab.task
def doc():
    generate_type_hierarchy()
    fab.local('sphinx-apidoc '
              '-o docs/developer_guide/api '
              '-f '
              '-e '
              'puresnmp '
              'puresnmp/test')
    with fab.lcd('docs'):
        fab.local('make html')


@fab.task
def publish():
    fab.local('rm -rf dist')
    fab.local('python3 setup.py bdist_wheel --universal')
    fab.local('python3 setup.py sdist')
    fab.local('twine upload dist/*')

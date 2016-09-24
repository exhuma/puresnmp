import fabric.api as fab


def generate_type_hierarchy():
    """
    Generate a document containing the available variable types.
    """
    fab.local('python -m puresnmp.types > docs/typetree.rst')


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

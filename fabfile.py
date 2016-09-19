import fabric.api as fab


@fab.task
def doc():
    fab.local('sphinx-apidoc '
              '-o docs/developer_guide/api '
              '-f '
              '-e '
              'puresnmp '
              'puresnmp/test')
    with fab.lcd('docs'):
        fab.local('make html')

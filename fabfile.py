import fabric.api as fab


@fab.task
def doc():
    with fab.lcd('docs'):
        fab.local('make html')

import fabric.api as fab


@fab.task
def doc():
    with fab.lcd('doc'):
        fab.local('make html')

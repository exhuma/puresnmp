import fabric


@fabric.task
def doc(ctx):
    ctx.run("rm -rf docs/api", replace_env=False, pty=True)
    ctx.run(
        "poetry run sphinx-apidoc -o docs/api -f -M puresnmp",
        replace_env=False,
        pty=True,
    )
    with ctx.cd("docs"):
        ctx.run("poetry run make html", replace_env=False, pty=True)

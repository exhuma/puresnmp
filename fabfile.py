from os.path import abspath
from typing import Any

import fabric


def regen_apidoc(ctx: Any, src: str, dest: str, is_nspkg: bool = False) -> None:
    ctx.run(f"rm -rf {dest}", replace_env=False, pty=True)
    nsopt = " --implicit-namespaces" if is_nspkg else ""
    ctx.run(
        f"./env/bin/sphinx-apidoc -o {dest} -f{nsopt} -e -M {src}",
        replace_env=False,
        pty=True,
    )


@fabric.task
def doc(ctx):
    regen_apidoc(ctx, "puresnmp", "docs/api")
    regen_apidoc(ctx, "puresnmp_plugins", "docs/plugins_api", True)
    opts = {
        "builddir": "_build",
        "sphinx": abspath("env/bin/sphinx-build"),
        "apidoc": abspath("env/bin/sphinx-apidoc"),
    }

    cmd = "{sphinx} -b html -d {builddir}/doctrees . {builddir}/html"

    with ctx.cd("docs"):
        ctx.run(cmd.format(**opts), replace_env=False, pty=False)


@fabric.task
def develop(ctx):
    """
    Set up a development environment
    """
    ctx.run("[ -d env ] || python3 -m venv env", replace_env=False)
    ctx.run("./env/bin/pip install -U pip", replace_env=False)
    ctx.run("./env/bin/pip install -e .[dev,test]", replace_env=False)

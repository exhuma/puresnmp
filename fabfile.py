from typing import Any

import fabric


def regen_apidoc(ctx: Any, src: str, dest: str, is_nspkg: bool = False) -> None:
    ctx.run(f"rm -rf {dest}", replace_env=False, pty=True)
    nsopt = " --implicit-namespaces" if is_nspkg else ""
    ctx.run(
        f"poetry run sphinx-apidoc -o {dest} -f{nsopt} -e -M {src}",
        replace_env=False,
        pty=True,
    )


@fabric.task
def doc(ctx):
    regen_apidoc(ctx, "puresnmp", "docs/api")
    regen_apidoc(ctx, "puresnmp_plugins", "docs/plugins_api", True)
    with ctx.cd("docs"):
        ctx.run("poetry run make html", replace_env=False, pty=True)

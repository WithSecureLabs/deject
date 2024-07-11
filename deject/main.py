"""!
@brief This is the main Deject application.
"""
from pathlib import Path
from typing import List
import r2pipe

try:
    import rzpipe
except OSError:
    pass

import typer
from tabulate import tabulate

import scripts
from deject.plugins import Deject

app = typer.Typer(name="Deject")


def check_path(file_path: str) -> Path:
    """Check the file path provided exists on the filesystem."""
    path = Path(file_path)
    if not path.exists():
        typer.secho(f"Path: '{file_path}' not found", fg=typer.colors.RED)
        raise typer.Abort()
    return path.resolve()


def check_r2_installed(file_path: Path):
    """Provide error message if r2 is not installed on operating system."""
    try:
        r = r2pipe.open(str(file_path), flags=["-2"])
    except Exception as err:
        try:
            r = rzpipe.open(str(file_path), flags=["-2"])
        except Exception as err:
            typer.secho(f"{err}. Please install either Rizin or Radare2 for your distribution", fg=typer.colors.RED)
            raise typer.Abort()
    return r

def pretty_print(results: dict):
    """Print the output of the plugins in a table"""
    typer.secho(
        tabulate(results["rows"], results["header"], tablefmt="fancy_grid"),
        fg=typer.colors.GREEN,
    )

@app.command()
def plugins():
    """List available plugins for deject"""
    try:
        plugins = scripts.names()
    except KeyError:
        typer.secho(f"No plugins found!", fg=typer.colors.RED, bold=True)
        raise typer.Abort()
    plugin_docs = []
    for plugin in plugins:
        plugin_docs.append([plugin, scripts.docs(plugin)])

    headers = ["Plugin", "Description"]

    typer.secho(
        tabulate(plugin_docs, headers=headers, tablefmt="fancy_grid"),
        fg=typer.colors.GREEN,
        bold=True,
    )

@app.command()
def run(
    file_path: str = typer.Argument(...),
    file_type: str = typer.Option("","--file-type", "-t", help="Run plugins for a file type. Examples include dmp, pe, pcap, pdf"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    save: bool = typer.Option(False, "--save", "-s"),
    exclude: List[str] = [],
    include: List[str] = [],
    plugin_args: str = typer.Argument(False)
):
    """Execute the available selection of plugins."""

    memory_dump_path = check_path(file_path)
    r2 = check_r2_installed(memory_dump_path)
    Deject.create(memory_dump=memory_dump_path, quiet=quiet, plugin_args=plugin_args, r2=r2)
    pre_include = ["pe_exports","list_libs","pe_hashlookup"]

    if file_type == "pe":
        pre_include = ["pe_packed","pe_exports","pe_hashes","pe_imports","pe_sections","malwareconfigextract","poshc2_check",
"c3_check","cobaltstrike_check","agenttesla_behaviour","list_libs","pe_hashlookup","pe_parser"]
    if file_type == "dmp":
        pre_include = ["list_exes","list_dlls","minidump_parser","inspect_mmaps","malwareconfigextract","poshc2_check",
"c3_check","cobaltstrike_check"]
    if file_type == "dmg":
        pre_include = ["dmg_hashes","pe_hashlookup"]
    if file_type == "elf":
        pre_include = ["pe_exports","pe_packed","elf_imports","elf_hashes","list_libs","pe_hashlookup","elf_parser"]
    if file_type == "macho":
        pre_include = ["pe_exports","elf_imports","dmg_hashes","list_libs","pe_hashlookup","macho_parser"]
    if file_type == "pdf":
        pre_include = ["pdf_modified","pdf_analytics","pdf_triage"]
    if file_type == "pcap":
        pre_include = ["zeek"]
    if len(include)>0:
        include = include[0].split(',')
        include = [plugin for plugin in scripts.names() if plugin in list(include)]
    if len(exclude)>0:
        exclude = exclude[0].split(',')
        if exclude[0] == "*":
            pre_include = []
        pre_include = [plugin for plugin in pre_include if plugin not in list(exclude)]
    include.extend(pre_include)
    plugins_to_run = set(include)

    if not plugins_to_run:
        typer.secho(f"No plugins selected to run", fg=typer.colors.RED, bold=True)
        raise typer.Abort()

    table = [
        ["file", memory_dump_path.name],
        ["file type", file_type],
        ["quiet mode", quiet],
        ["save dumps", save],
        ["excluded plugins", exclude],
        ["plugin args", plugin_args],
    ]
    typer.secho(
        f"\n ######################### [ EXECUTING DEJECT ] ##########################\n",
        fg=typer.colors.CYAN,
    )
    typer.secho(
        tabulate(table, headers=["Deject", "Setting"], tablefmt="fancy_grid"),
        fg=typer.colors.CYAN,
    )
    typer.secho(f"Running the selected plugins: {plugins_to_run}\n", fg=typer.colors.CYAN)

    with typer.progressbar(plugins_to_run) as progress:
        for plugin in progress:
            typer.secho(f"\n[running plugin: {plugin}]", fg=typer.colors.YELLOW, bold=True)
            # if the plugin returns a dict then we will use it to pretty print the result of the execution           
            res = scripts.run(plugin)
            if type(res) == dict:
                pretty_print(res)
    return 0


@app.command()
def help(plugin: str = typer.Argument(...)):
    """Show plugin help"""
    if plugin in scripts.names():
        imported = getattr(__import__("scripts", fromlist=[plugin]), plugin)
        try: 
            imported.help()
        except Exception:
            typer.secho(f"No help for plugin: {plugin}.",fg=typer.colors.RED)
    else:
        typer.secho(f"Plugin ({plugin}) does not exist!",fg=typer.colors.RED)
    
    return 0



if __name__ == "__main__":
    app()

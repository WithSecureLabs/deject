"""!
@brief Check the PE file to see if it has packed sections.
"""
from deject.plugins import Deject
from typer import secho, colors


@Deject.plugin
def pe_packed():
    """Run checks against the PE file to see if sections are packed"""
    sections = Deject.r2_handler.cmdj("iSj entropy")
    rows = []
    secho("Checking if packed...", fg=colors.BRIGHT_BLUE)
    for section in sections.get('sections'):
        packed = ""
        if section.get('entropy') is not None:
            if float(section.get('entropy')) > 6:
                packed = "X"
                if Deject.quiet:
                    rows.append(
                        [section.get("name"), section.get("entropy"), packed],
                    )
        if not Deject.quiet:
            rows.append([section.get("name"), section.get("entropy"), packed])
    res = {"header": ["Section", "Entropy", "Packed"], "rows": rows}
    return res


def help():
    print("""
PE Packed plugin
SYNOPSIS <filename>
Reads a PE file and checks if the sections in the file are packed.
This plugin takes no additional arguments.
""")

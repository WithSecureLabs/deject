import pytest
import deject.main

def test_macho_parser():
    assert deject.main.run("tests/data/hello.macho","","","",["*"],["macho_parser"],"False") == 0

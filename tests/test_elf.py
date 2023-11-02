import pytest
import deject.main

def test_elf_hashes():
    assert deject.main.run("tests/data/hello","","","",["*"],["elf_hashes"],"") == 0

def test_elf_imports():
    assert deject.main.run("tests/data/hello","","","",["*"],["elf_imports"],"") == 0

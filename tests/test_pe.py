import pytest
import deject.main

def test_pe_hashes():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["pe_hashes"],"") == 0

def test_pe_imports():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["pe_imports"],"") == 0

def test_pe_sections():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["pe_sections"],"") == 0

def test_pe_checks():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["pe_packed"],"") == 0

def test_pe_hashlookup():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["pe_hashlookup"],"") == 0

def test_pe_exports():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["pe_exports"],"") == 0

def test_pe_signatures():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["pe_signatures"],"") == 0
import pytest
import deject.main

def test_cobaltstrike_check():
    assert deject.main.run("tests/data/hello","","","",["*"],["cobaltstrike_check"],"") == 0

def test_poshc2_check():
    assert deject.main.run("tests/data/hello","","","",["*"],["poshc2_check"],"") == 0

def test_c3_check():
    assert deject.main.run("tests/data/hello","","","",["*"],["c3_check"],"") == 0

def test_malwareconfigextract_check():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["malwareconfigextract"],"") == 0
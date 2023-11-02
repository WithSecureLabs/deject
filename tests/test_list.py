import pytest
import deject.main

def test_list_bofs():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["list_bofs"],"") == 0

def test_list_dlls():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["list_dlls"],"") == 0

def test_list_exes():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["list_exes"],"") == 0

def test_list_libs():
    assert deject.main.run("tests/data/hello.exe","","","",["*"],["list_libs"],"") == 0

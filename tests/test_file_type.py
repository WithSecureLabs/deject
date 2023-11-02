import pytest
import deject.main

def test_file_type_elf():
    assert deject.main.run("tests/data/hello","elf","","",[],[],"") == 0

def test_file_type_pe():
    assert deject.main.run("tests/data/hello.exe","pe","","",[],[],"") == 0

def test_file_type_pdf():
    assert deject.main.run("tests/data/hello.pdf","pdf","","",[],[],"False") == 0

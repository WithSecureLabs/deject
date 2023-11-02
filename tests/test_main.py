import pytest
import deject.main

def test_main():
    assert deject.main.run("tests/data/hello","","","",[],[],"") == 0

import pytest
import deject.main

def test_pdf_modified():
    assert deject.main.run("tests/data/hello.pdf","","","",["*"],["pdf_modified"],"False") == 0

def test_pdf_triage():
    assert deject.main.run("tests/data/hello.pdf","","","",["*"],["pdf_triage"],"False") == 0

def test_pdf_analytics():
    assert deject.main.run("tests/data/hello.pdf","","","",["*"],["pdf_analytics"],"False") == 0

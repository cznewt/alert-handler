import os

import pytest

from conftest import ah


def test_load_secrets_reads_files_skips_dotfiles_and_empty(workdir):
    secrets = workdir / "secrets"
    (secrets / "chat-token").write_text("  s3cr3t-value\n")
    (secrets / "empty").write_text("\n")
    (secrets / "..data").write_text("kubernetes symlink farm")
    (secrets / "subdir").mkdir()
    assert ah.load_secrets() == {"chat-token": "s3cr3t-value"}


def test_load_secrets_without_directory_is_empty(tmp_path):
    assert ah.load_secrets(str(tmp_path / "nowhere")) == {}


def test_redactor_replaces_long_values_only():
    redact = ah.Redactor({"a": "short", "b": "long-secret-value", "c": "long-secret-value-extended"})
    assert redact("token=long-secret-value-extended and long-secret-value, pin short") == "token=*** and ***, pin short"
    assert redact(RuntimeError("failed with long-secret-value")) == "failed with ***"


def test_list_runbooks_names_only(workdir):
    runbooks = workdir / "runbooks"
    (runbooks / "b.sh").write_text("#!/bin/sh\n")
    (runbooks / "a.sh").write_text("#!/bin/sh\n")
    (runbooks / ".hidden").write_text("")
    (runbooks / "dir").mkdir()
    assert ah.list_runbooks() == ["a.sh", "b.sh"]
    assert ah.list_runbooks(str(workdir / "nowhere")) == []


def test_resolve_runbook_refuses_to_escape_the_directory(workdir):
    (workdir / "outside.sh").write_text("#!/bin/sh\n")
    with pytest.raises(RuntimeError, match="escapes"):
        ah.resolve_runbook("../outside.sh")


def test_resolve_runbook_names_what_is_available(workdir):
    (workdir / "runbooks" / "recycle.sh").write_text("#!/bin/sh\n")
    assert ah.resolve_runbook("recycle.sh") == os.path.realpath(str(workdir / "runbooks" / "recycle.sh"))
    with pytest.raises(RuntimeError, match="available: recycle.sh"):
        ah.resolve_runbook("missing.sh")

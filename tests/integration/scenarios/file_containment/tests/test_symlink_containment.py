"""Legacy defaults follow symlinks; explicit hardening rejects them on POSIX."""

import json
import os
from pathlib import Path
import time

import pytest

from utils.test_service import FluentBitTestService

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX containment policy")


def run_config(tmp_path, inputs, outputs, ready):
    config = tmp_path / "test.yaml"
    config.write_text(f"""
service:
  flush: 0.2
  grace: 1
  log_level: debug
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
{inputs}
  outputs:
{outputs}
""")
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(ready, timeout=30, interval=0.1)
        time.sleep(2)
    finally:
        service.stop()
    return Path(service.flb.log_file).read_text()


@pytest.mark.parametrize("plugin", ["tail", "blob"])
@pytest.mark.parametrize("follow_symlinks", [None, True, False], ids=["default", "follow", "harden"])
def test_input_symlink_policy(tmp_path, plugin, follow_symlinks):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (source / "regular.log").write_text("allowed\n")
    (outside / "secret.log").write_text("secret\n")
    (source / "link.log").symlink_to(outside / "secret.log")
    (source / "linked").symlink_to(outside, target_is_directory=True)
    output = tmp_path / "output"
    options = "      read_from_head: true\n" if plugin == "tail" else ""
    if follow_symlinks is not None:
        options += f"      follow_symlinks: {str(follow_symlinks).lower()}\n"
    # A second instance exercises a symlink ancestor, including glob expansion.
    inputs = "".join(f"""    - name: {plugin}
      path: {pattern}
      tag: {plugin}.test
{options}""" for pattern in [source / "*.log", source / "linked/*.log"])
    if plugin == "tail":
        outputs = f"""    - name: file
      match: '*'
      path: {tmp_path}
      file: output
      format: plain"""
        run_config(tmp_path, inputs, outputs, lambda: output.exists())
        expected = ["allowed"] if follow_symlinks is False else ["allowed", "secret", "secret"]
        assert sorted(json.loads(line)["log"] for line in output.read_text().splitlines()) == expected
    else:
        # Blob registration is visible in the debug log without a cloud backend.
        log = run_config(tmp_path, inputs, "    - name: null\n      match: '*'", lambda: True)
        assert f"blob scan add: {source / 'regular.log'}," in log
        for linked in [source / "link.log", source / "linked/secret.log"]:
            assert (f"blob scan add: {linked}," in log) == (follow_symlinks is not False)


@pytest.mark.parametrize("ancestor", [False, True], ids=["leaf", "directory"])
@pytest.mark.parametrize("dynamic", [False, True], ids=["static", "dynamic"])
@pytest.mark.parametrize("follow_symlinks", [None, True, False], ids=["default", "follow", "harden"])
def test_output_symlink_policy(tmp_path, ancestor, dynamic, follow_symlinks):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim"
    victim.write_text("untouched\n")
    destination = tmp_path / "destination"
    destination.mkdir()
    if ancestor:
        (destination / "link").symlink_to(outside, target_is_directory=True)
        filename = "link/victim"
    else:
        (destination / "victim").symlink_to(victim)
        filename = "victim"
    configured_path = str(destination)
    if dynamic and ancestor:
        configured_path += "/$dirname"
        filename = "victim"
    configured_file = '$filename' if dynamic else filename
    policy = "" if follow_symlinks is None else f"      follow_symlinks: {str(follow_symlinks).lower()}\n"
    marker = tmp_path / "success"
    run_config(tmp_path, f"""    - name: dummy
      dummy: '{{"filename":"{filename}","dirname":"link","message":"data"}}'
      samples: 1""", f"""    - name: file
      match: '*'
      path: '{configured_path}'
      file: '{configured_file}'
{policy}      mkdir: true
      fallback_file: fallback
      format: plain
    - name: file
      match: '*'
      path: {tmp_path}
      file: success
      format: plain""", lambda: marker.exists())
    if follow_symlinks is False:
        assert victim.read_text() == "untouched\n"
    else:
        assert "data" in victim.read_text()
    assert "data" in marker.read_text()


@pytest.mark.parametrize("follow_symlinks", [None, True, False], ids=["default", "follow", "harden"])
def test_rotation_symlink_policy(tmp_path, follow_symlinks):
    outside = tmp_path / "outside"
    outside.mkdir()
    destination = tmp_path / "destination"
    destination.symlink_to(outside, target_is_directory=True)
    policy = "" if follow_symlinks is None else f"      follow_symlinks: {str(follow_symlinks).lower()}\n"
    marker = tmp_path / "success"
    run_config(tmp_path, """    - name: dummy
      samples: 8
      rate: 4""", f"""    - name: file
      match: '*'
      path: {destination}
      file: output
{policy}      rotate: true
      rotate_max_size: 1
      rotate_max_files: 2
      rotate_gzip: true
    - name: file
      match: '*'
      path: {tmp_path}
      file: success""", lambda: marker.exists())
    if follow_symlinks is False:
        assert list(outside.iterdir()) == []
    else:
        assert (outside / "output").exists()
        assert list(outside.glob("output.*.gz"))

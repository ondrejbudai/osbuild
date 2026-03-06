import os
import subprocess
from unittest.mock import patch


def load_stage(name):
    """Load a stage module that has no .py extension"""
    import importlib.util, importlib.machinery
    path = os.path.join(os.path.dirname(__file__), "..", "..", "stages", name)
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@patch("subprocess.run")
def test_fatimage_basic(mocked_run, tmp_path):
    mod = load_stage("org.osbuild.fatimage")
    tree = str(tmp_path / "tree")
    source = str(tmp_path / "source")
    os.makedirs(tree)
    os.makedirs(source)
    os.makedirs(os.path.join(source, "EFI/BOOT"), exist_ok=True)
    (tmp_path / "source" / "EFI" / "BOOT" / "grubx64.efi").touch()

    mod.main(tree, {"tree": {"path": source}}, {
        "filename": "images/efiboot.img",
        "size": "20MB",
    })

    # First call: mkfs.vfat, second call: mcopy
    assert mocked_run.call_count == 2
    mkfs_args = mocked_run.call_args_list[0][0][0]
    assert mkfs_args[0] == "mkfs.vfat"
    assert mkfs_args[-1].endswith("images/efiboot.img")

    mcopy_args = mocked_run.call_args_list[1][0][0]
    assert mcopy_args[0] == "mcopy"
    assert "-s" in mcopy_args
    assert "-i" in mcopy_args
    assert "::" in mcopy_args

    img = os.path.join(tree, "images/efiboot.img")
    assert os.path.exists(img)
    assert os.path.getsize(img) == 20_000_000


@patch("subprocess.run")
def test_fatimage_with_label_and_volid(mocked_run, tmp_path):
    mod = load_stage("org.osbuild.fatimage")
    tree = str(tmp_path / "tree")
    source = str(tmp_path / "source")
    os.makedirs(tree)
    os.makedirs(source)
    (tmp_path / "source" / "test.txt").touch()

    mod.main(tree, {"tree": {"path": source}}, {
        "filename": "boot.img",
        "size": "10MB",
        "label": "ANACONDA",
        "volid": "7B7795E7",
    })

    mkfs_args = mocked_run.call_args_list[0][0][0]
    assert "-n" in mkfs_args
    idx = mkfs_args.index("-n")
    assert mkfs_args[idx + 1] == "ANACONDA"
    assert "-i" in mkfs_args
    idx = mkfs_args.index("-i")
    assert mkfs_args[idx + 1] == "7B7795E7"


@patch("subprocess.run")
def test_fatimage_empty_source(mocked_run, tmp_path):
    """Empty source tree should create filesystem but skip mcopy"""
    mod = load_stage("org.osbuild.fatimage")
    tree = str(tmp_path / "tree")
    source = str(tmp_path / "source")
    os.makedirs(tree)
    os.makedirs(source)

    mod.main(tree, {"tree": {"path": source}}, {
        "filename": "empty.img",
        "size": "1MB",
    })

    # Only mkfs.vfat, no mcopy since source is empty
    assert mocked_run.call_count == 1
    assert mocked_run.call_args[0][0][0] == "mkfs.vfat"

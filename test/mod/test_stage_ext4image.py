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
def test_ext4image_basic(mocked_run, tmp_path):
    mod = load_stage("org.osbuild.ext4image")
    tree = str(tmp_path / "tree")
    source = str(tmp_path / "source")
    os.makedirs(tree)
    os.makedirs(source)

    mod.main(tree, {"tree": {"path": source}}, {
        "filename": "LiveOS/rootfs.img",
        "size": "3GB",
        "uuid": "383367fa-6a09-4def-8c30-507e0b3cf1f7",
    })

    assert mocked_run.call_count == 1
    args = mocked_run.call_args[0][0]
    assert args[0] == "mkfs.ext4"
    assert "-U" in args
    assert "383367fa-6a09-4def-8c30-507e0b3cf1f7" in args
    assert "-d" in args
    assert args[-1].endswith("LiveOS/rootfs.img")

    img = os.path.join(tree, "LiveOS/rootfs.img")
    assert os.path.exists(img)
    assert os.path.getsize(img) == 3_000_000_000


@patch("subprocess.run")
def test_ext4image_with_label(mocked_run, tmp_path):
    mod = load_stage("org.osbuild.ext4image")
    tree = str(tmp_path / "tree")
    source = str(tmp_path / "source")
    os.makedirs(tree)
    os.makedirs(source)

    mod.main(tree, {"tree": {"path": source}}, {
        "filename": "rootfs.img",
        "size": "1GB",
        "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "label": "MyLabel",
    })

    args = mocked_run.call_args[0][0]
    assert "-L" in args
    idx = args.index("-L")
    assert args[idx + 1] == "MyLabel"


@patch("subprocess.run")
def test_ext4image_creates_parent_dirs(mocked_run, tmp_path):
    mod = load_stage("org.osbuild.ext4image")
    tree = str(tmp_path / "tree")
    source = str(tmp_path / "source")
    os.makedirs(tree)
    os.makedirs(source)

    mod.main(tree, {"tree": {"path": source}}, {
        "filename": "deep/nested/dir/image.img",
        "size": "100MB",
        "uuid": "11111111-2222-3333-4444-555555555555",
    })

    assert os.path.isdir(os.path.join(tree, "deep/nested/dir"))

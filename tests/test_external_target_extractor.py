from security_framework.classification.external_target_extractor import extract_external_targets


def test_extracts_git_clone_repo_target():
    targets = extract_external_targets({"type": "command", "command": "git clone https://github.com/org/repo"})
    assert {"type": "repo", "url": "https://github.com/org/repo", "source": "git clone https://github.com/org/repo"} in targets


def test_extracts_pip_package_target():
    targets = extract_external_targets({"type": "command", "command": "pip install requests"})
    assert targets == [
        {
            "type": "package",
            "ecosystem": "pypi",
            "name": "requests",
            "version": None,
            "source": "pip install requests",
        }
    ]


def test_extracts_local_package_target():
    targets = extract_external_targets({"type": "command", "command": "pip install ."})
    assert targets == [{"type": "local_package", "path": ".", "source": "pip install ."}]


def test_extracts_requirements_file_target():
    targets = extract_external_targets({"type": "command", "command": "pip install -r requirements.txt"})
    assert targets == [{"type": "requirements_file", "path": "requirements.txt", "source": "pip install -r requirements.txt"}]


def test_extracts_url_target():
    targets = extract_external_targets({"type": "command", "command": "curl https://example.com/install.sh"})
    assert targets == [{"type": "url", "url": "https://example.com/install.sh", "source": "curl https://example.com/install.sh"}]

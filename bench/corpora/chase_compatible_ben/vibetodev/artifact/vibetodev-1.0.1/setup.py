"""Transforme n'importe quel projet vibecode en parcours d'apprentissage."""
from setuptools import setup, find_packages
from pathlib import Path

this_dir = Path(__file__).parent
long_description = (this_dir / "README.md").read_text(encoding="utf-8") if (this_dir / "README.md").exists() else ""

setup(
    name="vibetodev",
    version="1.0.1",
    description="Transforme n'importe quel projet vibecode en parcours d'apprentissage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="ConnectPro",
    license="MIT",
    keywords="learning education code-analysis obsidian ast",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Education",
        "Topic :: Software Development :: Code Generators",
    ],
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "vibetodev=vibetodev.cli:main",
        ],
    },
    python_requires=">=3.8",
)

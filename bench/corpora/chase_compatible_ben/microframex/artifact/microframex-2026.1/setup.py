from setuptools import setup, find_packages

setup(
    name="microframex",
    version="2026.1",
    author="唐旭东",
    description="一个轻量级数据框架",
    packages=find_packages(),
    install_requires=[
        "openpyxl",
        "sqlalchemy",
        "colorama"
    ],
    python_requires=">=3.7",
)
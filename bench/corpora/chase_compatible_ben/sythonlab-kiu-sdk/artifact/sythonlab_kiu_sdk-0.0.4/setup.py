from setuptools import setup, find_packages

setup(
    name="sythonlab_kiu_sdk",
    version="0.0.4",
    packages=find_packages(), install_requires=[
        "requests>=2.34.2",
        "pandas>=3.0.3",
        "python-dotenv>=1.2.2",
        "xmltodict>=1.0.4",
    ],
    url="https://github.com/sythonlab/SythonLab-Kiu-Sdk",
    author="José Angel Alvarez Abraira",
    author_email="sythonlab@gmail.com",
    description="Sython Lab KIU SDK",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)

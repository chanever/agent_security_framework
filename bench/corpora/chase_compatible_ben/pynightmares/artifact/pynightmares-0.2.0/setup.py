from setuptools import setup, find_packages

setup(
    name='pynightmares',
    version='0.2.0',
    description='A collection of funny and strange Python scripts',
    long_description="Крутой пакетик, почитай на гите",
    author='mrf0rtuna4',
    author_email='heypers.team@gmail.com',
    url='https://github.com/mrf0rtuna4/PythonicNightmares',
    packages=find_packages(),
    install_requires=[
        # мда
    ],
    entry_points={
        'console_scripts': [
            'pynightmares=nightmares.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
)
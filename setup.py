#!/usr/bin/python3

# <@byt3n33dl3> from byt3n33dl3.github.io (AdverXarial).
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

from setuptools import setup, find_packages

setup(
    name="bloodpengu-python",
    version="1.4.2",
    description="Data collector in Python for BloodPengu APM",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    author="byt3n33dl3",
    url="https://github.com/byt3n33dl3/gxc-BloodPengu.py",
    license="Apache-2.0",
    python_requires=">=3.7",
    install_requires=[
        "paramiko>=3.0.0",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    py_modules=["bloodpengu_python"],
    package_data={
        "modules": ["*.py"],
    },
    entry_points={
        "console_scripts": [
            "bloodpengu-python=bloodpengu_python:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: Apache Software License",
        "Environment :: Console",
        "Topic :: Security",
    ],
)

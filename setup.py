from setuptools import setup

setup(
    name="bloodpengu-python",
    version="1.3.9",
    description="Data collector in Python for BloodPengu APM",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    author="byt3n33dl3",
    url="https://github.com/byt3n33dl3/gxc-BloodPengu.py",
    license="Apache 2.0",
    python_requires=">=3.7",
    install_requires=[
        "paramiko>=3.0.0",
    ],
    package_dir={"": "src"},
    py_modules=["bloodpengu_python"],
    entry_points={
        "console_scripts": [
            "bloodpengu-python=bloodpengu_python:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: Apache 2.0",
        "Environment :: Console",
        "Topic :: Security",
    ],
)
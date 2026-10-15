from setuptools import setup, find_packages

setup(
    name="authrecon-cli",
    version="0.9.1",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "requests>=2.31.0",
        "pyyaml>=6.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "authrecon=authrecon.cli:cli",
        ],
    },
    author="AuthRecon Team",
    description="CLI tool for AuthRecon API",
    python_requires=">=3.8",
)

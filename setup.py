from setuptools import find_packages, setup

setup(
    name="pst",
    python_requires=">=3.10",
    packages=find_packages(),
    entry_points={
        "console_scripts": ["pypst = pst:main"],
    },
)

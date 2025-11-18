import os
from collections import OrderedDict
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), "requirements.txt",),'r',encoding='utf-16') as f:
    dependencies = f.read().strip().split("\n")

setup(
    name="pocshift",
    author="Kairan Sun",
    packages=["pocshift"] + find_packages(),
    install_requires=dependencies,
    entry_points={
        "console_scripts": [
            "pocshift-parse=pocshift.poc_abstraction.poc_abstraction:main",
            "pocshift-match=pocshift.candidate_matching.candidate_matching:main",
        ]
    },
)

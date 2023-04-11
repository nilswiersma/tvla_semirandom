from setuptools import find_packages, setup

from test import *

setup(
    name='tvla_semirandom',
    version='0.0.2',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'numpy', 'scipy'
    ],
)
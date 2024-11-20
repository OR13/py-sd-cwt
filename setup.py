from setuptools import find_packages, setup

setup(
    name='sd_cwt',
    packages=find_packages(include=['sd_cwt']),
    version='0.1.0',
    description='Selective Disclosure for CBOR Web Tokens',
    author='Orie Steele',
    install_requires=[],
    setup_requires=['pytest-runner'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
)
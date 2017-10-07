#!/usr/bin/env python
from setuptools import setup

setup(
    name='yrd',
    version='0.5.0',
    description='cjdns for humans and cyborgs',
    author='kpcyrd',
    author_email='git at rxv.cc',
    url='https://github.com/kpcyrd/yrd',
    packages=['yrd', 'yrd.cjdns'],
    entry_points={
        'console_scripts': [
            'yrd = yrd.yrd:main'
        ]
    }
)

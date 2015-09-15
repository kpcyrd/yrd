#!/usr/bin/env python
from distutils.core import setup

setup(name='yrd',
      version='0.3',
      description='cjdns for humans and cyborgs',
      author='kpcyrd',
      author_email='git at rxv.cc',
      url='https://github.com/kpcyrd/yrd',
      packages=['yrd', 'yrd.cjdns'],
      scripts=['bin/yrd']
     )

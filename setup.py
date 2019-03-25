#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

requirements = []

setup_requirements = [
    'pytest-runner',
]

test_requirements = [
    'pytest',
]

setup(
    name='scrapy-s3-http-cache',
    version='0.1.0',
    description="S3 storage backend for Scrapy's HTTP cache middleware.",
    author='Luiz Francisco Rodrigues da Silva',
    author_email='luizfrdasilva@gmail.com',
    url='https://github.com/heylouiz/scrapy-s3-http-cache',
    packages=find_packages(include=['scrapy_s3_http_cache']),
    include_package_data=True,
    install_requires=requirements,
    license="MIT license",
    zip_safe=False,
    keywords='scrapy http cache extension',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    setup_requires=setup_requirements,
)

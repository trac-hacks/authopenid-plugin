from setuptools import setup
import os
import sys

PACKAGE = 'TracAuthOpenId'
VERSION = '0.4.5'

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()

install_requires = [
    "python-openid >= 2.1.0",
    ]

if sys.version_info[:2] < (2,6):
    install_requires.extend([
        'simplejson',
        ])

setup(
    name=PACKAGE,
    version=VERSION,
    description='OpenID plugin for Trac',
    long_description=README + "\n\n" + CHANGES,
    platforms = ['Any'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Plugins",
        "Environment :: Web Environment",
        "Framework :: Trac",
        "Intended Audience :: System Administrators",
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: BSD License",
        ],
    keywords='trac openid',
    author='Dalius Dobravolskas',
    author_email='dalius@sandbox.lt',
    maintainer='Jeff Dairiki',
    maintainer_email='dairiki@dairiki.org',
    url='https://github.com/dairiki/authopenid-plugin/',
    license='Trac license (BSD-like)',

    packages=['authopenid'],
    package_data={
        'authopenid': [
            'templates/*.html',
            'htdocs/css/*.css',
            'htdocs/images/*.gif',
            'htdocs/images/*.ico',
            'htdocs/js/*.js'
            ],
        },

    entry_points={
        'trac.plugins': [
            '%s = authopenid' % PACKAGE,
            ],
        },

    install_requires=install_requires,
    extras_require = {
        'teams': ['python-openid-teams'],
        },
    )

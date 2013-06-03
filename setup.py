from setuptools import setup, find_packages
import os
import sys
import warnings

PACKAGE = 'TracAuthOpenId'
VERSION = '1.0a1'

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()

install_requires = [
    "python-openid >= 2.2.0",
    ]

if sys.version_info[:2] < (2,6):
    install_requires.extend([
        'simplejson',
        ])

tests_require = [
    "mock >= 1.0",
    "WebOb",
    "WebTest",
    ]

if sys.version_info[:2] < (2,7):
    tests_require.extend([
        'unittest2',
        ])

    # Get rid of annoying warning which results from running
    #
    #     python -Wd setup.py test
    #
    # with unittest2 under py2.6
    warnings.filterwarnings(
        'ignore', r'Use of a TestResult without an addSkip method',
        DeprecationWarning)

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
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: BSD License",
        ],
    keywords='trac openid',
    author='Dalius Dobravolskas',
    author_email='dalius@sandbox.lt',
    maintainer='Jeff Dairiki',
    maintainer_email='dairiki@dairiki.org',
    url='https://github.com/dairiki/authopenid-plugin/',
    license='Trac license (BSD-like)',

    packages=find_packages(),

    # NB: this doesn't include the data files when building sdists
    package_data={
        'authopenid': [
            'templates/*.html',
            'htdocs/openid-selector/css/*.css',
            'htdocs/openid-selector/images/*.gif',
            'htdocs/openid-selector/images/*.png',
            'htdocs/openid-selector/js/openid-jquery.js',
            'htdocs/openid-selector/js/openid-??.js',
            'htdocs/openid-selector/js/openid-??_??.js',
            ],
        },

    entry_points={
        'trac.plugins': [
            # This just determines which modules trac loads initially.
            # I don't think the entry point names matter.
            '%s = authopenid' % PACKAGE,
            ],
        },

    install_requires=install_requires,

    test_suite='authopenid.tests.suite',
    tests_require=tests_require,
    )

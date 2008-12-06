from setuptools import setup

PACKAGE = 'TracAuthOpenId'
VERSION = '0.1.7'

setup(
        name=PACKAGE,
        version=VERSION,
        description='OpenID plugin for Trac',
        author='Dalius Dobravolskas',
        author_email='dalius@sandbox.lt',
        url='http://hg.sandbox.lt/authopenid-plugin',
        packages=['authopenid'],
        entry_points={'trac.plugins': '%s = authopenid' % PACKAGE},
        package_data={'authopenid': ['templates/*.html', 'htdocs/css/*.css']},
        download_url='http://trac.sandbox.lt/auth/raw-attachment/wiki/AuthOpenIdPlugin/TracAuthOpenId-0.1.7dev.tar.gz',
        install_requires = [
            "python-openid>=2.1.0"
        ],
)


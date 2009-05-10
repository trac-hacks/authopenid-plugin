from setuptools import setup

PACKAGE = 'TracAuthOpenId'
VERSION = '0.2'

setup(
        name=PACKAGE,
        version=VERSION,
        description='OpenID plugin for Trac',
        license='Trac license',
        author='Dalius Dobravolskas',
        author_email='dalius@sandbox.lt',
        url='http://trac.sandbox.lt/auth/wiki/AuthOpenIdPlugin',
        packages=['authopenid'],
        entry_points={'trac.plugins': '%s = authopenid' % PACKAGE},
        include_package_data = True,
        package_data={'authopenid': ['templates/*.html', 'htdocs/css/*.css']},
        install_requires = [
            "python-openid>=2.1.0"
        ],
)


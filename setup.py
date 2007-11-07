from setuptools import setup

PACKAGE = 'TracAuthOpenId'
VERSION = '0.1'

setup(name=PACKAGE,
      version=VERSION,
      packages=['authopenid'],
      entry_points={'trac.plugins': '%s = authopenid' % PACKAGE},
      package_data={'authopenid': ['templates/*.html', 'htdocs/css/*.css']},
)


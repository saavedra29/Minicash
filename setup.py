from setuptools import setup
from setuptools import find_packages

setup(name='Minicash',
      version='0.1',
      description='The funniest joke in the world',
      url='http://github.com/storborg/funniest',
      author='Flying Circus',
      author_email='flyingcircus@example.com',
      license='MIT',
      scripts=['minicash/minicash', 'minicash/minicashd', 'minicash/quickDataGen'], 
      packages=['minicash', 'minicash.utils', 'minicash.tests'],
      install_requires=[
          'json-rpc','python-daemon', 'python-gnupg', 'lockfile'
      ],
      zip_safe=False)

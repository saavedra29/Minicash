from setuptools import setup

setup(name='Minicash',
      version='0.1',
      description='A cryptocurrency without blockchain',
      url='http://github.com/saavedra29/Minicash',
      author='Aristides Tomaras',
      author_email='arisgold29@gmail.com',
      license='MIT',
      scripts=['minicash/minicash', 'minicash/minicashd', 'minicash/quickDataGen'], 
      packages=['minicash', 'minicash.utils'],
      install_requires=[
          'json-rpc','python-daemon', 'python-gnupg', 'lockfile'
      ],
      zip_safe=False)

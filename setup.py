from setuptools import setup

setup(name='Minicash',
    version='0.4.0',
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
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Framework :: AsyncIO',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security :: Cryptography'
    ],
    keywords='Cryptocurrency gpg',
    zip_safe=False)

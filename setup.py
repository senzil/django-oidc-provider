import os
from setuptools import (
    find_packages,
    setup,
)

version = {}
with open("./oidc_provider/version.py") as fp:
    exec(fp.read(), version)

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-rest-framework-oidc-provider',
    version=version['__version__'],
    packages=find_packages(),
    include_package_data=True,
    license='MIT License',
    description='OpenID Connect Provider implementation for Django and Django Rest Framework.',
    long_description='http://github.com/senzil/senzil-django-oidc-provider',
    url='http://github.com/senzil/senzil-django-oidc-provider',
    author='Pablo Daniel González',
    author_email='pablodgonzalez@gmail.com',
    zip_safe=False,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
    test_suite='runtests.runtests',
    tests_require=[
        'pyjwkest>=1.3.0',
        'mock>=2.0.0',
    ],

    install_requires=[
        'python_jwt>=3.3.2',
        'pyjwkest>=1.3.0',
    ],
)

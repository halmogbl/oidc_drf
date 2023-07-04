from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name='oidc_drf',
    version='1.2.1',
    author='Hamad Almogbl',
    author_email='hamad.almogbl@gmail.com',
    description='Django DRF OIDC Auth library: Securely authenticate users using OIDC in Django DRF. Supports Code Flow and Code Flow With PKCE. Easy integration with React Js or any front-end framework.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/halmogbl/oidc_drf',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=[
        "Django >= 3.2",
        "josepy",
        "requests",
        "cryptography",
        'djangorestframework',
    ],
)


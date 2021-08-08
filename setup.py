from setuptools import setup

setup(
    name="PasswordsSniffer",
    version="0.0.1",

    py_modules=["PasswordsSniffer"],
    
    install_requires=["scapy"],

    author="Maurice Lambert",
    author_email="mauricelambert434@gmail.com",
    maintainer="Maurice Lambert",
    maintainer_email="mauricelambert434@gmail.com",
 
    description="This module sniff username and password of unprotected protocols.",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mauricelambert/PasswordsSniffer",
    project_urls={
        "Executable": "https://mauricelambert.github.io/info/python/security/PasswordsSniffer.pyz",
        "Documentation": "https://mauricelambert.github.io/info/python/security/PasswordsSniffer.html",
    },
    download_url="https://mauricelambert.github.io/info/python/security/PasswordsSniffer.pyz",
 
    include_package_data=True,
 
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        "Natural Language :: English",
        "Programming Language :: Python :: 3.9"
    ],
 
    keywords=["PasswordsSniffer"],
    platforms=['Windows', 'Linux', "MacOS"],
    license="GPL-3.0 License",

    entry_points = {
        'console_scripts': [
            'PasswordsSniffer = PasswordsSniffer:main'
        ],
    },
    python_requires='>=3.6',
)
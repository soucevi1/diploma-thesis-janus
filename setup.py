from setuptools import setup

setup(
    name='janus_exploit',
    version='1.0',
    description='Merges DEX and APK to exploit Janus vulnerability',
    author='Vit Soucek',
    author_email='soucevi1@fit.cvut.cz',
    packages=find_packages(),
    classifiers=[
        'Intended Audience :: Education',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Security',
        'Operating System :: Android',
        'Topic :: System :: Installation/Setup',
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'janus = janus_exploit.janus_exploit:main',
        ],
    },
    install_requires=['click'],
)

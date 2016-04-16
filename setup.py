from setuptools import setup, find_packages
import os

version = '0.1'

install_requires = [
    'setuptools',
    'webob',
    'oauthlib>=0.6.2',
    'requests-oauthlib>=0.5.0',
    ]

tests_require = [
    ]

setup(name='trilith.oauth2',
      version=version,
      description="Trilith UI based on the Cromlech Framework",
      long_description=open("README.txt").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      classifiers=[
        "Programming Language :: Python",
        ],
      keywords='Oauth2 Trilith',
      author='Dolmen Team',
      author_email='dolmen@list.dolmen-project.org',
      url='http://gitweb.dolmen-project.org',
      license='ZPL',
      packages=find_packages('src', exclude=['ez_setup']),
      package_dir={'': 'src'},
      namespace_packages=['trilith', ],
      include_package_data=True,
      zip_safe=False,
      tests_require=tests_require,
      install_requires=install_requires,
      extras_require={'test': tests_require},
      entry_points="""
      # -*- Entry points: -*-
      """,
      )

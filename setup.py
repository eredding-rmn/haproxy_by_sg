from setuptools import setup, find_packages

setup(
    name="haproxy_by_sg",
    version="0.0.1",
    description="configure haproxy via aws security group",
    author="RetailMeNot Engineering Operations",
    author_email="aus-eng-ops@rmn.com",
    url="http://github.com/WhaleShark/haproxy_by_sg",
    install_requires=[
        "boto >= 2.27.0",
        "Jinja2 >= 2.7.1",
        "argparse >= 1.1"
    ],
    packages=find_packages(),
    classifiers=[
        "Development Status :: 2 - Pre-Pre-Alpha",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Intended Audience :: Developers"],
    test_suite="tests",
    entry_points={
        "console_scripts": [
            'update_haproxy = haproxy_by_sg.update_haproxy:main',
        ]},
    include_package_data=True,
)

<<<<<<< HEAD
from setuptools import setup, find_packages

setup(
    name="logsense",
    version="0.1.0",
    # Kodların src klasörü altında olduğunu sisteme söylüyoruz
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "pyyaml",
        "matplotlib",
        "jinja2",
    ],
    entry_points={
        "console_scripts": [
            "logsense=cli:main", # src/cli.py içindeki main fonksiyonunu tetikler
        ],
    },
)
=======
from setuptools import setup, find_packages

setup(
    name="logsense",
    version="0.1.0",
    # Kodların src klasörü altında olduğunu sisteme söylüyoruz
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "pyyaml",
        "matplotlib",
        "jinja2",
    ],
    entry_points={
        "console_scripts": [
            "logsense=cli:main", # src/cli.py içindeki main fonksiyonunu tetikler
        ],
    },
)
>>>>>>> 7834c630897abf4b894656d3d1fc88421ace8501

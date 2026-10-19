from setuptools import setup


setup(
    name="logsense",
    version="0.1.0",
    description="CLI log parser and analyzer",
    package_dir={"": "src"},
    py_modules=[
        "cli",
        "main",
        "models",
        "parsers",
        "report",
        "rules",
        "storage",
    ],
    python_requires=">=3.11",
    install_requires=[
        "pyyaml",
        "matplotlib",
        "jinja2",
    ],
    entry_points={
        "console_scripts": [
            "logsense=cli:main",
        ],
    },
)
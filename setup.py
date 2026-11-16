from setuptools import setup, find_packages

setup(
    name="hello-cat",
    version="1.0.0",
    description="Hello Cat - automated TryHackMe/CTF reconnaissance tool",
    author="Hello Cat Contributors",
    packages=find_packages(include=["modules", "modules.*"]),
    py_modules=["main"],
    install_requires=[
        "requests>=2.31.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "hello-cat=main:main",
        ],
    },
    python_requires=">=3.8",
)

from setuptools import setup, find_packages

setup(
    name="apex-toolkit",
    version="1.0.0",
    packages=find_packages(),
    py_modules=['apex'],
    install_requires=[
        "frida-tools",
        "google-genai",
        "python-dotenv",
        "pyapktool",
        "scapy",
    ],
    entry_points={
        "console_scripts": [
            "apex=apex:main",
        ],
    },
)

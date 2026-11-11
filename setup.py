import os
from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

app_packages = ["app"] + [f"app.{p}" for p in find_packages("core/app")]
connector_packages = ["connectors"] + [f"connectors.{p}" for p in find_packages("connectors")]

setup(
    name="ethio-cyber-shield",
    version="3.0.0.dev1",
    description="Sovereign Cybersecurity Detection, Fraud Interception & 48-Hour Incident-Readiness Platform for Ethiopian Critical Infrastructure",
    author="Musab Hassen Aliyi, Osman Mohammed Seid, Kedist Eyasu Embaye, Yoseph Abebe Ersedo, Omer Mohammed Seid, Efrem Mola Genebo",
    author_email="security@ethiocybershield.et",
    license="Apache-2.0",
    url="https://github.com/Rammiso/ethio-cybershield",
    package_dir={
        "app": "core/app",
        "connectors": "connectors",
    },
    packages=app_packages + connector_packages,
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ecs=app.cli:main",
            "ecs-server=app.cli:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Financial and Insurance Industry",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
)

from setuptools import setup, find_packages

setup(
    name="ethio-cyber-shield-sdk",
    version="1.1.0",
    description="Official Python SDK with Transactional Outbox for Ethio-Cyber-Shield (ECS)",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "flask": ["flask>=2.0.0"],
        "fastapi": ["fastapi>=0.95.0", "starlette>=0.26.0"],
        "django": ["django>=3.2.0"],
    },
    author="Ethio-Cyber-Shield Platform Team",
    license="Apache-2.0",
    python_requires=">=3.9",
)

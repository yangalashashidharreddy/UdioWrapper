from setuptools import setup, find_packages

with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip()]

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name='udio_wrapper',
    version='0.0.4',
    description='Generates songs using the Udio API using textual prompts.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Flowese',
    packages=find_packages(),
    install_requires=requirements,
    python_requires='>=3.8',
)

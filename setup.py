"""
setup.py
========
Installation script for the ArabGuard SDK.

Install (development):
    pip install -e .

Install from source:
    pip install .

Install from PyPI (once published):
    pip install arabguard
"""

from setuptools import setup, find_packages
import os

# ── Read long description from README ────────────────────────────────────────
_HERE = os.path.abspath(os.path.dirname(__file__))

def _read_file(filename: str, fallback: str = "") -> str:
    path = os.path.join(_HERE, filename)
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    return fallback


long_description = _read_file(
    "README.md",
    fallback=(
        "ArabGuard – Multi-layer Arabic/English prompt-injection "
        "and jailbreak detection SDK."
    ),
)

setup(
    # ── Identity ──────────────────────────────────────────────────────────
    name             = "arabguard",
    version          = "1.0.0",
    author           = "ArabGuard",
    description      = (
        "Multi-layer Arabic/English prompt-injection and jailbreak detection SDK"
    ),
    long_description          = long_description,
    long_description_content_type = "text/markdown",
    license          = "MIT",

    # ── Keywords / classifiers ────────────────────────────────────────────
    keywords = [
        "arabic", "nlp", "security", "prompt-injection",
        "jailbreak", "llm", "ai-safety", "egyptian-arabic", "franko",
    ],
    classifiers = [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Text Processing :: Linguistic",
        "Natural Language :: Arabic",
    ],

    # ── Packages ──────────────────────────────────────────────────────────
    packages         = find_packages(exclude=["tests*", "docs*", "examples*"]),
    python_requires  = ">=3.8",

    # ── Core dependencies ─────────────────────────────────────────────────
    install_requires = [
        "beautifulsoup4>=4.11.0",   # HTML parsing / tag stripping
        "emoji>=2.0.0",             # Emoji detection and removal
        "nltk>=3.8",                # English word corpus (for deobfuscation)
    ],

    # ── Optional / extra dependencies ─────────────────────────────────────
    extras_require = {
        # AI layer (MARBERT model from Hugging Face)
        "ai": [
            "transformers>=4.30.0",
            "torch>=2.0.0",
            "scipy>=1.9.0",
        ],
        # Data analysis and batch processing utilities
        "data": [
            "pandas>=1.5.0",
        ],
        # Everything (install with: pip install arabguard[full])
        "full": [
            "pandas>=1.5.0",
            "transformers>=4.30.0",
            "torch>=2.0.0",
            "scipy>=1.9.0",
        ],
        # Development tools
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "isort>=5.12",
            "mypy>=1.0",
            "flake8>=6.0",
        ],
    },

    # ── Entry points (CLI) ────────────────────────────────────────────────
    entry_points = {
        "console_scripts": [
            "arabguard=arabguard.cli:main",
        ],
    },

    # ── Package data ──────────────────────────────────────────────────────
    include_package_data = True,
    zip_safe             = False,

    # ── Project URLs ──────────────────────────────────────────────────────
    project_urls = {
        "Source"     : "https://github.com/arabguard/arabguard",
        "Bug Reports": "https://github.com/arabguard/arabguard/issues",
    },
)

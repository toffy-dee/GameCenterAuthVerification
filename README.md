# API iOS Validation Lambda Function

This is the Lambda function for verification of GameCenter fetchItemsForIdentityVerificationSignature. Below are the instructions to set up the environment, install dependencies, and package the function for deployment.

## Prerequisites

- Python 3.x installed on your local machine
- AWS CLI configured with the necessary permissions

## Setup and Installation

  Create a virtual environment (optional but recommended):
  ```bash
    python3 -m venv venv
    source venv/bin/activate
  ```

  ### Build package for arm64 architecture
  ```bash
    mkdir package_arm64
    pip install \
        --platform manylinux2014_aarch64 \
        --target=package_arm64 \
        --implementation cp \
        --python-version 3.12 \
        --only-binary=:all: \
        --upgrade \
        cryptography requests

    cp app.py package_arm64/
  ```

  ```bash
    cd package_arm64
    zip -r9 ../api_ios-validation_arm64.zip .
    cd ..
  ```

  ### Build package for arm64 architecture
  ```bash
    mkdir package_x86_64
    pip install \
        --platform manylinux2014_x86_64 \
        --target=package_x86_64 \
        --implementation cp \
        --python-version 3.12 \
        --only-binary=:all: \
        --upgrade \
        cryptography requests

    cp app.py package_x86_64/
  ```

  ```bash
    cd package_x86_64
    zip -r9 ../api_ios-validation_x86_64.zip .
    cd ..
  ```
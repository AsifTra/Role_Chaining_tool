## AWS IAM Role Chaining Tool

This tool works in either discovery mode in which you can detect all roles that can cause a role chaining, and in an automated mode which automatically assumes the chained role for you.

```console
python3 roleChaining.py -m discovery -p <profile>
python3 roleChaining.py -m automated -p <based role profile> -r <target role name>
```

finally you can clean all localy created profiles with:

```console
python3 roleChaining.py -m cleanup
```

## AWS IAM keys validator

Testing IAM key pairs at mass or separately

```console
python3 IAM_keys_validator.py -f <filename in a <ACCESS_KEY>:<SECRET_KEY>(:SESSION_TOKEN) format>
python3 IAM_keys_validator.py -ak <ACCESS_KEY> -sk <SECRET_KEY>
python3 IAM_keys_validator.py -ak <ACCESS_KEY> -sk <SECRET_KEY> -st <SESSION_TOKEN>
```

## Installation
```
git clone https://github.com/AsifTra/aws_iam_tools.git
cd aws_tools/
pip3 install -r requirements.txt
```

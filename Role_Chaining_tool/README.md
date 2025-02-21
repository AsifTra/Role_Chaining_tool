## AWS IAM Role Chaining Tool

This tool works in either discovery mode in which you can detect all roles that can cause a role chaining, and in an automated mode which automatically assumes the chained role for you.

```console
python3 roleChaining.py -m discovery -p <profile>
python3 roleChaining.py -m automated -p <based role profile> -r <target role name>
```

Finally you can clean all localy created profiles with:

```console
python3 roleChaining.py -m cleanup
```

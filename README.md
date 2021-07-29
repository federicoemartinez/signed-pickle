# signed-pickle

Pickle is insecure: If you unpickle data from an untrusted source, you can
end up executing arbitrary code.

This package addresses that signing the pickle output with a shared key. Hence,
when you unpickle data, the signature is verified and the data is only unpickled
if it matches. The package also allows to add expiration to the signed data and it
is checked before unpickling.

```python
DEFAULT_HMAC_ALGORITHM = 'sha256'

def dumps(key: bytes, obj, protocol=None, fix_imports=True, algorithm=DEFAULT_HMAC_ALGORITHM,
          expiration: Optional[timedelta] = None) -> bytes
    
def dump(key: bytes, obj, file, protocol=None, fix_imports=True, algorithm=DEFAULT_HMAC_ALGORITHM,
         expiration: Optional[timedelta] = None)
    
def loads(key: bytes, data: bytes, fix_imports=True, encoding="ASCII", errors="strict",
          algorithm=DEFAULT_HMAC_ALGORITHM)
    
def load(key: bytes, file, fix_imports=True, encoding="ASCII", errors="strict",
         algorithm=DEFAULT_HMAC_ALGORITHM)
```





    


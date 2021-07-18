import datetime
import hmac
import pickle
from datetime import timedelta
from typing import Optional

DEFAULT_HMAC_ALGORITHM = 'sha256'


def dumps(key: bytes, obj, protocol=None, fix_imports=True, algorithm=DEFAULT_HMAC_ALGORITHM,
          expiration: Optional[timedelta] = None) -> bytes:
    message = pickle.dumps(obj, protocol=protocol, fix_imports=fix_imports)
    if expiration is not None:
        timestamp = (datetime.datetime.utcnow() + expiration).timestamp()
        message = str(timestamp).encode('ascii') + b"_" + message
    message = (b"1" if expiration is not None else b"0") + b"_" + message
    digest = hmac.new(key, message, algorithm).digest()
    return str(len(digest)).encode('ascii') + b"_" + digest + b"_" + message


def dump(key: bytes, obj, file, protocol=None, fix_imports=True, algorithm=DEFAULT_HMAC_ALGORITHM,
         expiration: Optional[timedelta] = None):
    file.write(dumps(key, obj, protocol, fix_imports, algorithm, expiration))



class InvalidDigestError(pickle.UnpicklingError):
    pass


class ExpiredPickleError(pickle.UnpicklingError):
    pass

class InvalidUsingExpirationValue(InvalidDigestError):
    pass

class InvalidExpirationValue(InvalidDigestError):
    pass


def loads(key: bytes, data: bytes, fix_imports=True, encoding="ASCII", errors="strict",
          algorithm=DEFAULT_HMAC_ALGORITHM):
    try:
        digest_length, rest_of_data = data.split(b"_", 1)
        saved_digest = rest_of_data[0:int(digest_length)]
        rest_of_data = rest_of_data[int(digest_length) + 1:]
    except Exception:
        raise InvalidDigestError("Unable to find digest in data")
    try:
        using_expiration, message = rest_of_data.split(b"_", 1)
    except ValueError:
        raise InvalidDigestError("Unable to find digest in data")
    if using_expiration not in (b"0", b"1"):
        raise InvalidUsingExpirationValue("Error checking for using expiration. It must be 1 or 0")

    if using_expiration == b'1':
        try:
            expiration_timestamp_bytestring, message = message.split(b"_", 1)
        except ValueError:
            raise InvalidDigestError("Unable to find expiration timestamp")
        try:
            expiration_timestamp = float(expiration_timestamp_bytestring)
        except ValueError:
            raise InvalidExpirationValue("Invalid timestamp for expiration")
        if datetime.datetime.utcnow().timestamp() > expiration_timestamp:
            raise ExpiredPickleError(f"Piclke data expired on {datetime.datetime.fromtimestamp(expiration_timestamp)}")
    message_prefix = using_expiration + b"_" + (
        expiration_timestamp_bytestring + b"_" if using_expiration == b'1' else b'')
    digest = hmac.new(key, message_prefix + message, algorithm).digest()
    if not hmac.compare_digest(saved_digest, digest):
        raise InvalidDigestError(f"Digests does not match. Expected: {digest.hex()}. Recived: {saved_digest.hex()}")
    return pickle.loads(message, fix_imports=fix_imports, encoding=encoding, errors=errors)


def load(key: bytes, file, fix_imports=True, encoding="ASCII", errors="strict",
         algorithm=DEFAULT_HMAC_ALGORITHM):
    data = file.read()
    return loads(key, data, fix_imports, encoding, errors, algorithm)

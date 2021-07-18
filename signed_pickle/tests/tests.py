import datetime
import hmac
import io
import pickle
from datetime import timedelta

import pytest
from freezegun import freeze_time

from signed_pickle import dumps, DEFAULT_HMAC_ALGORITHM, loads, InvalidDigestError, ExpiredPickleError, \
    InvalidUsingExpirationValue, dump, load, InvalidExpirationValue

key = b'SECRET_KEY'

def test_dumps():
    test_string = "test string"
    s = dumps(key, test_string)
    _test_dumped_string(s, test_string)

def test_dump():
    f = io.BytesIO()
    test_string = "test string"
    dump(key, test_string, f)
    s = f.getvalue()
    _test_dumped_string(s, test_string)


def _test_dumped_string(s, test_string):
    assert b"_" in s
    assert s.count(b"_") == 3
    digest_size, digest, using_expiration, data = s.split(b"_", 3)
    assert using_expiration == b"0"
    assert digest == hmac.new(key, b'0_' + pickle.dumps(test_string), DEFAULT_HMAC_ALGORITHM).digest()
    assert int(digest_size) == len(digest)


@freeze_time("2021-07-18")
def test_dumps_with_expiration():
    test_string = "test string"
    one_minute = timedelta(minutes=1)
    s = dumps(key, test_string, expiration=one_minute)
    assert b"_" in s
    digest_size, rest_of_data = s.split(b"_", 1)
    assert digest_size == b'32'
    digest = rest_of_data[0:32]
    rest_of_data = rest_of_data[33:]
    using_expiration, timestamp, data = rest_of_data.split(b"_",2)
    assert using_expiration == b"1"
    assert digest == hmac.new(key, b'1_' +timestamp + b"_"+ pickle.dumps(test_string), DEFAULT_HMAC_ALGORITHM).digest()
    assert float(timestamp) == (datetime.datetime.utcnow() + one_minute).timestamp()


def test_loads():
    test_data = {"a":1, 2:"test", "test_key":[1,2,3]}
    s = dumps(key, test_data)

    restored_data = loads(key, s)
    assert test_data == restored_data

def test_load():
    fo = io.BytesIO()
    test_data = {"a":1, 2:"test", "test_key":[1,2,3]}
    dump(key, test_data, fo)
    fi = io.BytesIO(fo.getvalue())
    restored_data = load(key, fi)
    assert test_data == restored_data

def test_loads_corrupted():
    test_data = {"a":1, 2:"test", "test_key":[1,2,3]}
    s = dumps(key, test_data)
    s1 = s + b"a"
    with pytest.raises(InvalidDigestError):
        loads(key, s1)
    s1 = b'1' + s
    with pytest.raises(InvalidDigestError):
        loads(key, s1)
    s1 = b'33_' + s
    with pytest.raises(InvalidDigestError):
        loads(key, s1)
    s1 = b'f_' + s
    with pytest.raises(InvalidDigestError):
        loads(key, s1)

def test_loads_using_expiration():
    test_data = {"a":1, 2:"test", "test_key":[1,2,3]}
    s = dumps(key, test_data, expiration=timedelta(hours=1))
    restored_data = loads(key, s)
    assert test_data == restored_data

def test_loads_expired_data():
    test_data = {"a": 1, 2: "test", "test_key": [1, 2, 3]}
    with freeze_time("2021-07-16"):
        s = dumps(key, test_data, expiration=timedelta(days=1))
    with freeze_time("2021-07-18"):
        with pytest.raises(ExpiredPickleError):
            loads(key, s)

def test_loads_invalid_using_timestamp():
    test_data = {"a": 1, 2: "test", "test_key": [1, 2, 3]}
    s = dumps(key, test_data)
    s = s.replace(b'0', b'5')
    with pytest.raises(InvalidUsingExpirationValue):
        loads(key, s)


def test_loads_invalid_not_using_timestamp_stored_as_using():
    s = b'32_\xd7\x15\xb3\x01=\xed\xcd,\xcc\xf9\xfdB\x16\xf8\x1d\r\xc2\xfc\x0eE\xc0\xea\x1d=|\xa0(\x01\xc3v\xc0D_1_\x80\x03}q\x00(X\x01\x00\x00\x00aq\x01K\x01K\x02X\x04\x00\x00\x00testq\x02X\x08\x00\x00\x00test5keyq\x03]q\x04(K\x01K\x02K\x03eu.'
    with pytest.raises(InvalidDigestError):
        loads(key, s)

def test_loads_using_expiration_non_float_timestamp():
    test_data = {"a":1, 2:"test", "test_key":[1,2,3]}
    s = dumps(key, test_data, expiration=timedelta(hours=1))
    s = s.replace(b'.', b'x')
    with pytest.raises(InvalidExpirationValue):
        loads(key, s)


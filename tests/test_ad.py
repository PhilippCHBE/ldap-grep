from datetime import datetime, timezone

from ldapgrep import ad


def test_uac_flags():
    assert ad.decode_uac(514) == ["ACCOUNTDISABLE", "NORMAL_ACCOUNT"]
    assert ad.decode_uac("66048") == ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"]
    assert ad.decode_uac(None) == []
    assert ad.decode_uac("garbage") == []


def test_is_disabled_defensive():
    assert ad.is_disabled(514) is True
    assert ad.is_disabled(512) is False
    assert ad.is_disabled(None) is False          # missing attribute -> enabled
    assert ad.is_disabled("") is False
    assert ad.is_disabled(["514"]) is True
    assert ad.is_disabled(b"514") is True


def test_is_password_expired():
    assert ad.is_password_expired(8389120) is True    # NORMAL_ACCOUNT | PASSWORD_EXPIRED
    assert ad.is_password_expired("8389122") is True  # + ACCOUNTDISABLE
    assert ad.is_password_expired(512) is False
    assert ad.is_password_expired(66048) is False     # DONT_EXPIRE_PASSWORD
    assert ad.is_password_expired(None) is False
    assert ad.is_password_expired("garbage") is False


def test_filetime():
    assert ad.filetime_to_datetime(0) is None
    assert ad.filetime_to_datetime("") is None
    assert ad.filetime_to_datetime("0") is None
    assert ad.filetime_to_datetime(9223372036854775807) is None
    dt = ad.filetime_to_datetime(133700000000000000)
    assert dt == datetime(2024, 9, 5, 8, 53, 20, tzinfo=timezone.utc)
    # ldap3 pre-formatted values
    assert ad.filetime_to_datetime(datetime(9999, 12, 31, tzinfo=timezone.utc)) is None
    assert ad.filetime_to_datetime(datetime(1601, 1, 1, tzinfo=timezone.utc)) is None
    assert ad.filetime_to_datetime(dt) == dt


def test_decode_value_never_and_dates():
    assert ad.decode_value("accountExpires", 0) == "never"
    assert ad.decode_value("accountExpires", 9223372036854775807) == "never"
    assert ad.decode_value("accountExpires", datetime(9999, 12, 31, tzinfo=timezone.utc)) == "never"
    assert ad.decode_value("msDS-UserPasswordExpiryTimeComputed", 9223372036854775807) == "never"
    assert ad.decode_value("msDS-UserPasswordExpiryTimeComputed", 0) == "never"
    assert ad.decode_value("lastLogon", 0) == ""
    assert ad.decode_value("lastLogon", datetime(1601, 1, 1, tzinfo=timezone.utc)) == ""
    assert ad.decode_value("whenCreated", "20240101120000.0Z", "%Y-%m-%d") == ad.format_datetime(
        datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc), "%Y-%m-%d")


def test_generalized_time_variants():
    assert ad.generalized_time_to_datetime("20240101120000Z") == datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert ad.generalized_time_to_datetime("20240101120000.123Z") == datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert ad.generalized_time_to_datetime("not a date") is None
    assert ad.generalized_time_to_datetime("") is None


def test_sid_and_guid():
    sid = b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\xe8\x03\x00\x00"
    assert ad.sid_to_str(sid) == "S-1-5-21-67305985-134678021-202050057-1000"
    assert ad.sid_to_str("S-1-5-32-544") == "S-1-5-32-544"
    assert ad.sid_to_str(b"\x01") == "\x01" or ad.sid_to_str(b"\x01")  # never raises
    import uuid
    u = uuid.uuid4()
    assert ad.guid_to_str(u.bytes_le) == str(u)
    assert ad.guid_to_str("{" + str(u) + "}") == str(u)


def test_bytes_to_text_binary_fallback():
    assert ad.bytes_to_text(b"hello") == "hello"
    assert ad.bytes_to_text(b"\xff\xd8\xff\xe0JFIF").startswith("base64:")


def test_group_type():
    assert ad.decode_group_type(-2147483646) == {"scope": "global", "category": "security"}
    assert ad.decode_group_type(8) == {"scope": "universal", "category": "distribution"}
    assert ad.decode_group_type(None) == {}

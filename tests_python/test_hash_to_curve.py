import pytest
from snowblind.curve import hash_to_curve


@pytest.mark.parametrize("message,x,y", [
    (b"", "c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
     "64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067"),
    (b"abc", "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
     "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"),
])
def test_rfc9380_j8_1(message, x, y):
    """Official vectors, https://www.rfc-editor.org/rfc/rfc9380#appendix-J.8.1."""
    assert hash_to_curve(message, b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_") == (int(x, 16), int(y, 16))

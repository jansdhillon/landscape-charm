from configparser import ConfigParser
from datetime import timedelta
import json
from types import SimpleNamespace

from charmlibs.interfaces.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
    PrivateKey,
)
import pytest

import settings_files


class ConfigReader:

    def __init__(self, tempfile):
        self.tempfile = tempfile

    def get_config(self) -> ConfigParser:
        config = ConfigParser()
        config.read(self.tempfile)
        return config


@pytest.fixture(autouse=True)
def capture_service_conf(tmp_path, monkeypatch) -> ConfigReader:
    """
    Redirect all writes to `SERVICE_CONF` to a tempfile within this fixture.
    Return a `ConfigReader` that reads from this file.

    This is set to `autouse=True` to avoid any attempts to write to the filesystem
    during tests, which typically throw an error if the real
    `/etc/landscape/service.conf` is not present.
    """
    conf_file = tmp_path / "service.conf"
    conf_file.write_text("")

    monkeypatch.setattr(settings_files, "SERVICE_CONF", str(conf_file))

    return ConfigReader(conf_file)


# Based on: https://github.com/canonical/haproxy-operator/blob/main/haproxy-operator/tests/unit/conftest.py


@pytest.fixture(scope="function", name="systemd_mock")
def systemd_mock_fixture(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("charms.operator_libs_linux.v1.systemd.service_reload", True)


@pytest.fixture(scope="function", name="ca_certificate_and_key")
def ca_certificate_and_key_fixture() -> tuple[Certificate, PrivateKey]:
    """Ca Certificate and private key."""
    private_key_ca = generate_private_key()
    ca = generate_ca(generate_private_key(), timedelta(days=10), "caname")
    return ca, private_key_ca


TEST_EXTERNAL_HOSTNAME_CONFIG = "landscape.local"


@pytest.fixture(scope="function", name="csr_certificate_and_key")
def csr_certificate_and_key_fixture(
    ca_certificate_and_key,
) -> tuple[CertificateSigningRequest, Certificate, PrivateKey]:
    """Ca Certificate and private key."""
    ca, private_key_ca = ca_certificate_and_key
    private_key = generate_private_key()
    csr = generate_csr(private_key, TEST_EXTERNAL_HOSTNAME_CONFIG)
    certificate = generate_certificate(csr, ca, private_key_ca, timedelta(days=5))
    return csr, certificate, private_key


@pytest.fixture(scope="function", name="certificates_relation_data")
def certificates_relation_data_fixture(
    csr_certificate_and_key,
    ca_certificate_and_key,
) -> dict[str, str]:
    """Mock tls_certificates relation data."""
    csr, cert, _ = csr_certificate_and_key
    ca_cert, _ = ca_certificate_and_key
    return {
        "certificates": json.dumps(
            [
                {
                    "ca": ca_cert.raw,
                    "certificate_signing_request": csr.raw,
                    "certificate": cert.raw,
                    "chain": [
                        cert.raw,
                        ca_cert.raw,
                    ],
                },
            ]
        )
    }


@pytest.fixture(scope="function", name="mock_certificate_and_key")
def mock_certificate_fixture(
    monkeypatch: pytest.MonkeyPatch,
    csr_certificate_and_key,
) -> tuple[Certificate, PrivateKey]:
    """Mock tls certificate from a tls provider charm."""
    _, certificate, private_key = csr_certificate_and_key

    provider_cert_mock = SimpleNamespace(certificate=certificate)
    monkeypatch.setattr(
        (
            "charmlibs.interfaces.tls_certificates"
            ".TLSCertificatesRequiresV4.get_assigned_certificate"
        ),
        lambda *args, **kwargs: (provider_cert_mock, private_key),
    )
    monkeypatch.setattr(
        (
            "charmlibs.interfaces.tls_certificates"
            ".TLSCertificatesRequiresV4.get_assigned_certificates"
        ),
        lambda *args, **kwargs: ([provider_cert_mock], private_key),
    )
    return certificate, private_key

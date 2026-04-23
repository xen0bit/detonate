"""Tests for infrastructure tracking (Phase 3.2)."""

import pytest
import tempfile
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from src.detonate.core.session import AnalysisSession, APICallRecord, InfrastructureRecord
from src.detonate.core.hooks.windows import WindowsHooks
from src.detonate.core.hooks.linux import LinuxHooks


@pytest.fixture
def temp_sample():
    """Create a temporary sample file for testing."""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
        f.write(b'MZ' + b'\x00' * 100)  # Minimal PE header
        temp_path = f.name
    yield temp_path
    import os
    os.unlink(temp_path)


def create_mock_ql():
    """Create mock Qiling instance."""
    ql = Mock()
    ql.mem = Mock()
    ql.mem.string = Mock(return_value="test")
    ql.mem.wstring = Mock(return_value="test")
    ql.os = Mock()
    ql.os.f_param_read = Mock(return_value=0x1000)
    ql.arch = Mock()
    ql.arch.pc = 0x401000
    ql.arch.regs = Mock()
    ql.arch.regs.rdi = 0x1000
    ql.arch.regs.rsi = 0x2000
    ql.arch.regs.rdx = 0x3000
    ql.arch.regs.r10 = 0x4000
    ql.arch.regs.rip = 0x401000
    return ql


class TestInfrastructureRecord:
    """Test InfrastructureRecord dataclass."""

    def test_infrastructure_record_creation(self):
        """Test creating an infrastructure record."""
        now = datetime.now(timezone.utc)
        infra = InfrastructureRecord(
            name="C2 Server: example.com",
            infrastructure_types=["command-and-control"],
            first_seen=now,
            last_seen=now,
            confidence="high",
        )
        
        assert infra.name == "C2 Server: example.com"
        assert infra.infrastructure_types == ["command-and-control"]
        assert infra.confidence == "high"
        assert len(infra.related_api_calls) == 0


class TestAnalysisSessionInfrastructure:
    """Test infrastructure tracking in AnalysisSession."""

    def test_add_infrastructure_new(self, temp_sample):
        """Test adding new infrastructure."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="abc123",
            platform="windows",
            architecture="x86",
        )
        
        now = datetime.now(timezone.utc)
        api_call = APICallRecord(
            timestamp=now,
            api_name="InternetConnectA",
            syscall_name=None,
            params={"lpszServerName": "example.com"},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        session.add_infrastructure(
            name="C2 Server: example.com",
            infrastructure_types=["command-and-control"],
            related_api_call=api_call,
        )
        
        assert len(session.infrastructure) == 1
        infra = session.infrastructure[0]
        assert infra.name == "C2 Server: example.com"
        assert infra.infrastructure_types == ["command-and-control"]
        assert len(infra.related_api_calls) == 1

    def test_add_infrastructure_duplicate(self, temp_sample):
        """Test adding duplicate infrastructure updates existing record."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="abc123",
            platform="windows",
            architecture="x86",
        )
        
        now = datetime.now(timezone.utc)
        api_call1 = APICallRecord(
            timestamp=now,
            api_name="InternetConnectA",
            syscall_name=None,
            params={"lpszServerName": "example.com"},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        api_call2 = APICallRecord(
            timestamp=now,
            api_name="HttpOpenRequestA",
            syscall_name=None,
            params={"lpszObjectName": "/beacon"},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        # Add same infrastructure twice
        session.add_infrastructure(
            name="C2 Server: example.com",
            infrastructure_types=["command-and-control"],
            related_api_call=api_call1,
        )
        session.add_infrastructure(
            name="C2 Server: example.com",
            infrastructure_types=["command-and-control"],
            related_api_call=api_call2,
        )
        
        # Should still have only one record, but with two API calls
        assert len(session.infrastructure) == 1
        assert len(session.infrastructure[0].related_api_calls) == 2

    def test_to_result_includes_infrastructure(self, temp_sample):
        """Test that to_result includes infrastructure."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="abc123",
            platform="windows",
            architecture="x86",
        )
        
        now = datetime.now(timezone.utc)
        api_call = APICallRecord(
            timestamp=now,
            api_name="InternetConnectA",
            syscall_name=None,
            params={"lpszServerName": "example.com"},
            return_value=0,
            address="0x401000",
            confidence="high",
        )
        
        session.add_infrastructure(
            name="C2 Server: example.com",
            infrastructure_types=["command-and-control"],
            related_api_call=api_call,
        )
        
        result = session.to_result()
        assert len(result.infrastructure) == 1
        assert result.infrastructure[0].name == "C2 Server: example.com"


class TestWindowsHooksInfrastructure:
    """Test Windows hooks track infrastructure."""

    def test_internet_connect_tracks_infrastructure(self, temp_sample):
        """Test InternetConnectA hook tracks C2 infrastructure."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="abc123",
            platform="windows",
            architecture="x86",
        )
        ql = create_mock_ql()
        ql.mem.string = Mock(return_value="malicious-c2.example.com")
        
        hooks = WindowsHooks(session, ql)
        hooks.hook_InternetConnectA(ql)
        
        assert len(session.infrastructure) == 1
        assert "malicious-c2.example.com" in session.infrastructure[0].name
        assert session.infrastructure[0].infrastructure_types == ["command-and-control"]

    def test_internet_connect_localhost_ignored(self, temp_sample):
        """Test localhost connections are not tracked as infrastructure."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="abc123",
            platform="windows",
            architecture="x86",
        )
        ql = create_mock_ql()
        ql.mem.string = Mock(return_value="127.0.0.1")
        
        hooks = WindowsHooks(session, ql)
        hooks.hook_InternetConnectA(ql)
        
        # Localhost should not be tracked
        assert len(session.infrastructure) == 0

    def test_http_open_request_tracks_endpoint(self, temp_sample):
        """Test HttpOpenRequestA hook tracks C2 endpoints."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="abc123",
            platform="windows",
            architecture="x86",
        )
        ql = create_mock_ql()
        ql.mem.string = Mock(side_effect=["GET", "/api/beacon"])
        
        hooks = WindowsHooks(session, ql)
        hooks.hook_HttpOpenRequestA(ql)
        
        assert len(session.infrastructure) == 1
        assert "/api/beacon" in session.infrastructure[0].name


class TestLinuxHooksInfrastructure:
    """Test Linux hooks track infrastructure."""

    def test_connect_tracks_ipv4_infrastructure(self, temp_sample):
        """Test connect syscall tracks IPv4 C2 infrastructure."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="def456",
            platform="linux",
            architecture="x86_64",
        )
        ql = create_mock_ql()
        
        # Mock sockaddr_in structure for 192.168.1.100:443
        # Family (2 bytes) = 2 (AF_INET) - little endian
        # Port (2 bytes) = 443 (0x01BB in network/big endian)
        # IP (4 bytes) = 192.168.1.100
        sockaddr_data = bytes([0x02, 0x00, 0x01, 0xBB, 192, 168, 1, 100])
        addr_ptr = 0x2000  # Mock address pointer
        
        # Set rsi to point to sockaddr structure
        ql.arch.regs.rsi = addr_ptr
        
        # Mock mem.read to return sockaddr data when reading from addr_ptr
        def mock_read(addr, length):
            offset = addr - addr_ptr
            if 0 <= offset < len(sockaddr_data) - length + 1:
                return sockaddr_data[offset:offset + length]
            return bytes(length)
        
        ql.mem.read = Mock(side_effect=mock_read)
        
        hooks = LinuxHooks(session, ql)
        hooks.hook_sys_connect(ql)
        
        assert len(session.infrastructure) == 1
        assert "192.168.1.100:443" in session.infrastructure[0].name

    def test_connect_tracks_ipv6_infrastructure(self, temp_sample):
        """Test connect syscall tracks IPv6 C2 infrastructure."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="def456",
            platform="linux",
            architecture="x86_64",
        )
        ql = create_mock_ql()
        
        # Mock sockaddr_in6 structure - IPv6 loopback ::1
        # Family (2 bytes) = 10 (AF_INET6) - little endian = 0x0A, 0x00
        # Port (2 bytes) = 443 (0x01BB in network/big endian)
        # Flowinfo (4 bytes) = 0
        # Address (16 bytes) = ::1 = 0000:0000:0000:0000:0000:0000:0000:0001
        # Scope id (4 bytes) = 0
        sockaddr_data = bytes([0x0A, 0x00, 0x01, 0xBB]) + bytes(4) + bytes(15) + bytes([0x01]) + bytes(4)
        addr_ptr = 0x2000
        
        ql.arch.regs.rsi = addr_ptr
        
        def mock_read(addr, length):
            offset = addr - addr_ptr
            if 0 <= offset < len(sockaddr_data) - length + 1:
                return sockaddr_data[offset:offset + length]
            return bytes(length)
        
        ql.mem.read = Mock(side_effect=mock_read)
        
        hooks = LinuxHooks(session, ql)
        hooks.hook_sys_connect(ql)
        
        # IPv6 loopback should not be tracked (starts with [::1])
        assert len(session.infrastructure) == 0

    def test_connect_cloud_metadata_detected(self, temp_sample):
        """Test connect to cloud metadata endpoint is detected."""
        session = AnalysisSession(
            sample_path=temp_sample,
            sample_sha256="def456",
            platform="linux",
            architecture="x86_64",
        )
        ql = create_mock_ql()
        
        # Mock AWS metadata endpoint 169.254.169.254:80
        sockaddr_data = bytes([0x02, 0x00, 0x00, 0x50, 169, 254, 169, 254])
        addr_ptr = 0x2000
        
        ql.arch.regs.rsi = addr_ptr
        
        def mock_read(addr, length):
            offset = addr - addr_ptr
            if 0 <= offset < len(sockaddr_data) - length + 1:
                return sockaddr_data[offset:offset + length]
            return bytes(length)
        
        ql.mem.read = Mock(side_effect=mock_read)
        
        hooks = LinuxHooks(session, ql)
        hooks.hook_sys_connect(ql)
        
        # Should have both infrastructure and technique detection
        assert len(session.infrastructure) == 1
        # Technique should be detected for cloud metadata access
        assert len(session.findings) >= 1

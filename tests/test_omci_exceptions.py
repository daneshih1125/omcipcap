#!/usr/bin/env python3
import pytest
from omci.omci import OMCIBaseline, OMCIPacket

def test_baseline_init_too_short():
    short_data = b'\x00\x01\x2d\x0a' + b'\x00' * 16
    
    with pytest.raises(ValueError) as excinfo:
        OMCIBaseline(short_data)
    
    assert "Baseline packet too short" in str(excinfo.value)

def test_baseline_trailer_missing_exception():
    data_40 = b'\x00\x01\x2d\x0a' + b'\x00' * 36
    
    with pytest.raises(ValueError) as excinfo:
        OMCIBaseline(data_40, ignore_trailer=False)
    
    assert "Baseline trailer missing" in str(excinfo.value)

def test_from_raw_too_short():
    tiny_data = b'\x00\x01\x02' 
    
    with pytest.raises(ValueError, match="Data too short"):
        OMCIPacket.from_raw(tiny_data)

def test_baseline_valid_length():
    valid_data = b'\x00\x01\x2d\x0a' + b'\x00' * 44
    pkt = OMCIBaseline(valid_data)
    assert len(pkt.content) == 32
    assert pkt.trailer is not None

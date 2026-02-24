#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong Yuan, Shih daneshih1125@gmail.com
# Licensed under the MIT License.

import sys
import os
from scapy.all import wrpcap, Ether, Raw
sys.path.append(os.getcwd())
from omci.omci import OmciAction, OmciResult

OLT_MAC = "00:00:00:00:00:02"
ONU_MAC = "00:00:00:00:00:01"

def msg_resp(action_val):
    return action_val | 0x20

def create_omci(tid, msg_type, me_class, inst_id, content=None, is_from_olt=True):
    """
    Directly pack the OMCI fields into a 48-byte binary buffer.
    No need for OMCIBaseline object creation during pcap generation.
    """
    # Header (8 bytes)
    header = tid.to_bytes(2, 'big')
    header += int(msg_type).to_bytes(1, 'big')
    header += b'\x0a'  # Device ID
    header += me_class.to_bytes(2, 'big')
    header += inst_id.to_bytes(2, 'big')

    # Content (32 bytes)
    if content is None:
        content = b'\x00' * 32
    else:
        content = content.ljust(32, b'\x00')

    # Trailer (4 bytes)
    trailer = b'\x00\x00\x00\x28'

    raw_payload = header + content + trailer

    # Encapsulate with Ethernet
    src = OLT_MAC if is_from_olt else ONU_MAC
    dst = ONU_MAC if is_from_olt else OLT_MAC

    # Using Raw() ensures Scapy treats the 48 bytes as the payload
    return Ether(dst=dst, src=src, type=0x88B5) / Raw(load=raw_payload)

def generate_mib_pcap(filename, mib_data_list):
    """
    mib_data_list: list of tuples (class_id, inst_id, attr_mask, data_bytes)
    """
    pkts = []
    tid = 1
    
    # MIB Upload Header
    pkts.append(create_omci(tid, OmciAction.MIB_UPLOAD, 2, 0))
    pkts.append(create_omci(tid, msg_resp(OmciAction.MIB_UPLOAD), 2, 0, 
                               content=len(mib_data_list).to_bytes(2, 'big'), is_from_olt=False))
    tid += 1

    for me_class, me_inst, mask, data in mib_data_list:
        # OLT Request Next
        pkts.append(create_omci(tid, OmciAction.MIB_UPLOAD_NEXT, 2, 0))
        # ONU Response: [Class(2) + Inst(2) + Mask(2) + Data(27)]
        upload_content = me_class.to_bytes(2, 'big') + me_inst.to_bytes(2, 'big') + \
                         mask.to_bytes(2, 'big') + data
        pkts.append(create_omci(tid, msg_resp(OmciAction.MIB_UPLOAD_NEXT), 2, 0, 
                                   content=upload_content, is_from_olt=False))
        tid += 1
    
    wrpcap(filename, pkts)
    print(f"Generated {filename} with {len(mib_data_list)} MIB entities.")

def main():
    # IP Host Config (Class 134): Mask 0x4000 = IP Address (4 bytes)
    ip_before = b'\x00\x00\x00\x00'
    ip_after  = b'\xc0\xa8\x01\x0a' # 192.168.1.10
    
    # Cardholder (Class 5): Mask 0x8000 = Actual Type (1 byte)
    card_type_base = b'\x30' # Type 48
    card_type_new  = b'\x31' # Type 49

    # --- Pcap 1:
    mib_v1 = [
        (2, 0, 0x8000, b'\x01'),                      # ONT Data: MIB Sync=1
        (134, 1, 0x4000, ip_before),                  # IP Host: 0.0.0.0
        (5, 257, 0x8000, card_type_base),             # Cardholder: Type 48
        (5, 258, 0x8000, b'\x47'),                    # Cardholder: Type 47
    ]
    generate_mib_pcap("mib_before.pcap", mib_v1)

    # --- Pcap 2: 
    mib_v2 = [
        (2, 0, 0x8000, b'\x01'),                      # ONT Data: MIB Sync=1
        (134, 1, 0x4000, ip_after),                   # IP Host: 192.168.1.10
        (5, 257, 0x8000, card_type_new),              # Cardholder: Type 49
        (262, 1, 0x8000, b'\x04\x00'),                # T-CONT 1: Alloc-ID 1024
    ]
    generate_mib_pcap("mib_after.pcap", mib_v2)

    # --- Pcap 3: 
    mib_omcc_96 = [
        (256, 0, 0x8000, b'ALCL'),                    # ONT-G: Vendor
        (257, 0, 0x4000, b'\x96'),                    # ONT2-G: OMCC Version = 0x96 (G.988 2010)
        (263, 1, 0x4000, b'\x00\x08'),                # ANI-G: Total T-CONT = 8
    ]
    generate_mib_pcap("mib_omcc_96.pcap", mib_omcc_96)

    # --- Pcap 4: 
    mib_omcc_a0 = [
        (256, 0, 0x8000, b'ALCL'),
        (257, 0, 0x4000, b'\xa0'),                    # ONT2-G: OMCC Version = 0xA0 (G.988 2012)
        (263, 1, 0x4000, b'\x00\x10'),                # ANI-G: Total T-CONT = 16
        (262, 1, 0x8000, b'\x04\x01'),                # T-CONT
    ]
    generate_mib_pcap("mib_omcc_a0.pcap", mib_omcc_a0)

    # --- Pcap 5: 
    mib_vendor_v1 = [
        (256, 0, 0x8000, b'HWTC'),
        (257, 0, 0x4000, b'\xa0'),                    # ONT2-G: OMCC Version = 0xA0 (G.988 2012)
        (355, 0, 0xc000, b'\x48\x47\x55\x01'),        # Mock Vendor 355 ME
    ]
    generate_mib_pcap("mib_vendor_v1.pcap", mib_vendor_v1)

    # --- Pcap 6: 
    mib_vendor_v2 = [
        (256, 0, 0x8000, b'HWTC'),
        (257, 0, 0x4000, b'\xa0'),                    # ONT2-G: OMCC Version = 0xA0 (G.988 2012)
        (355, 0, 0xc000, b'\x53\x46\x55\x00'),        # Mock Vendor 355 ME
    ]
    generate_mib_pcap("mib_vendor_v2.pcap", mib_vendor_v2)

    print("\nSuccess! Now you can run:")
    print("omcidiff mib_before.pcap mib_after.pcap")
    print("omcidiff mib_omcc_96.pcap mib_omcc_a0.pcap")

if __name__ == "__main__":
    main()

# vim: set ts=4 sw=4 et:

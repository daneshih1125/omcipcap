#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (c) 2026 Dong Yuan, Shih daneshih1125@gmail.com
# Licensed under the MIT License.

import struct

ME_CLASS_NAMES = {
    2: "ONT Data",
    5: "Cardholder",
    6: "Circuit Pack",
    7: "Software Image",
    11: "PPTP Ethernet UNI",
    24: "Ethernet PM History Data",
    45: "MAC Bridge Service Profile",
    46: "MAC bridge configuration data",
    47: "MAC bridge port configuration data",
    48: "MAC bridge port designation data",
    49: "MAC bridge port filter table data",
    50: "MAC bridge port bridge table data",
    51: "MAC Bridge PM History Data",
    52: "MAC Bridge Port PM History Data",
    53: "Physical path termination point POTS UNI",
    58: "Voice service profile",
    78: "VLAN tagging operation configuration data",
    79: "MAC bridge port filter preassign table",
    82: "PPTP Video UNI",
    84: "VLAN tagging filter data",
    89: "Ethernet PM History Data 2",
    90: "PPTP Video ANI",
    130: "802.1P Mapper Service Profile",
    131: "OLT-G",
    133: "ONU Power Shedding",
    134: "IP host config data",
    135: "IP host performance monitoring history data",
    136: "TCP/UDP config data",
    137: "Network address",
    138: "VoIP config data",
    139: "VoIP voice CTP",
    140: "Call control performance monitoring history data",
    141: "VoIP line status",
    142: "VoIP media profile",
    143: "RTP profile data",
    144: "RTP performance monitoring history data",
    145: "Network dial plan table",
    146: "VoIP application service profile",
    147: "VoIP feature access codes",
    148: "Authentication security method",
    149: "SIP config portal",
    150: "SIP agent config data",
    151: "SIP agent performance monitoring history data",
    152: "SIP call initiation performance monitoring history data",
    153: "SIP user data",
    154: "MGC config portal",
    155: "MGC config data",
    156: "MGC performance monitoring history data",
    157: "Large string",
    158: "ONT remote debug",
    159: "Equipment protection profile",
    160: "Equipment extension package",
    171: "Extended VLAN tagging operation configuration data",
    256: "ONT-G",
    257: "ONT2-G",
    262: "T-CONT",
    263: "ANI-G",
    264: "UNI-G",
    266: "GEM interworking Termination Point",
    267: "GEM Port PM History Data",
    268: "GEM Port Network CTP",
    271: "GAL TDM profile",
    272: "GAL Ethernet profile",
    273: "Threshold Data 1",
    274: "Threshold Data 2",
    275: "GAL TDM PM History Data",
    276: "GAL Ethernet PM History Data",
    277: "Priority queue-G",
    278: "Traffic Scheduler-G",
    279: "Protection data",
    280: "Traffic descriptor",
    281: "Multicast GEM interworking termination point",
    287: "OMCI",
    288: "Managed entity",
    289: "Attribute",
    290: "Dot1X Port Extension Package",
    291: "Dot1X configuration profile",
    292: "Dot1X performance monitoring history data",
    293: "Radius performance monitoring history data",
    296: "Ethernet PM History Data 3",
    297: "Port mapping package",
    298: "Dot1 rate limiter",
    299: "Dot1ag maintenance domain",
    300: "Dot1ag maintenance association",
    301: "Dot1ag default MD level",
    302: "Dot1ag MEP",
    303: "Dot1ag MEP status",
    304: "Dot1ag MEP CCM database",
    305: "Dot1ag CFM stack",
    306: "Dot1ag chassis-management info",
    307: "Octet string",
    308: "General purpose buffer",
    309: "Multicast operations profile",
    310: "Multicast subscriber config info",
    311: "Multicast Subscriber Monitor",
    312: "FEC PM History Data",
    318: "File transfer controller",
    321: "Ethernet Frame PM History Data DS",
    322: "Ethernet Frame PM History Data US",
    329: "Virtual Ethernet interface point",
    330: "Generic status portal",
    331: "ONU-E",
    332: "Enhanced security control",
    334: "Ethernet frame extended PM",
    335: "SNMP configuration data",
    336: "ONU dynamic power management control",
    340: "TR-069 management server",
    341: "GEM port network CTP performance monitoring history data",
    342: "TCP/UDP performance monitoring history data",
    425: "Ethernet frame extended PM 64 bit"
}

ME_SPEC = {
    # 9.1.3 ONU data
    2: ("ONT Data", [
        ("MIB Data Sync", 1, "u8")
    ]),
    # 9.1.5 Cardholder
    5: ("Cardholder", [
        ("Actual Plug-in Unit Type", 1, "u8"),
        ("Expected Plug-in Unit Type", 1, "u8"),
        ("Expected Port Count", 1, "u8"),
        ("Expected Equipment Id", 20, "str"),
        ("Actual Equipment Id", 20, "str"),
        ("Protection Profile Pointer", 1, "hex"),
        ("Invoke Protection Switch", 1, "u8")
    ]),
    # 9.1.6 Circuit pack
    6: ("Circuit Pack", [
        ("Type", 1, "u8"),
        ("Number of ports", 1, "u8"),
        ("Serial Number", 8, "hex"),
        ("Version", 14, "str"),
        ("Vendor Id", 4, "hex"),
        ("Administrative State", 1, "u8"),
        ("Operational State", 1, "u8"),
        ("Bridged or IP Ind", 1, "u8"),
        ("Equipment Id", 20, "str"),
        ("Card Configuration", 1, "u8"),
        ("Total T-CONT Buffer Number", 1, "u8"),
        ("Total Priority Queue Number", 1, "u8"),
        ("Total Traffic Scheduler Number", 1, "u8"),
        ("Power Shed Override", 4, "u32")
    ]),
    # 9.1.4 Software image
    7: ("Software Image", [
        ("Version", 14, "str"),
        ("Is committed", 1, "u8"),
        ("Is active", 1, "u8"),
        ("Is valid", 1, "u8")
    ]),
    # 9.5.1 Physical path termination point Ethernet UNI
    11: ("PPTP Ethernet UNI", [
        ("Expected Type", 1, "u8"),
        ("Sensed Type", 1, "u8"),
        ("Auto Detection Configuration", 1, "u8"),
        ("Ethernet Loopback Configuration", 1, "u8"),
        ("Administrative State", 1, "u8"),
        ("Operational State", 1, "u8"),
        ("Configuration Ind", 1, "u8"),
        ("Max Frame Size", 2, "u16"),
        ("DTE or DCE", 1, "u8"),
        ("Pause Time", 2, "u16"),
        ("Bridged or IP Ind", 1, "u8"),
        ("ARC", 1, "u8"),
        ("ARC Interval", 1, "u8"),
        ("PPPoE Filter", 1, "u8"),
        ("Power Control", 1, "u8")
    ]),
    # 9.5.2 Ethernet performance monitoring history data
    24: ("Ethernet PM History Data", [
        ("Interval End Time", 1, "u8"),
        ("Threshold Data 1/2 Id", 2, "hex"),
        ("FCS errors Drop events", 4, "u32"),
        ("Excessive Collision Counter", 4, "u32"),
        ("Late Collision Counter", 4, "u32"),
        ("Frames too long", 4, "u32"),
        ("Buffer overflows on Receive", 4, "u32"),
        ("Buffer overflows on Transmit", 4, "u32"),
        ("Single Collision Frame Counter", 4, "u32"),
        ("Multiple Collisions Frame Counter", 4, "u32"),
        ("SQE counter", 4, "u32"),
        ("Deferred Transmission Counter", 4, "u32"),
        ("Internal MAC Transmit Error", 4, "u32"),
        ("Carrier Sense Error", 4, "u32"),
        ("Alignment Error Counter", 4, "u32"),
        ("Internal MAC Receive Error", 4, "u32")
    ]),
    # 9.3.1 MAC bridge service profile
    45: ("MAC Bridge Service Profile", [
        ("Spanning tree ind", 1, "u8"),
        ("Learning ind", 1, "u8"),
        ("Port bridging ind", 1, "u8"),
        ("Priority", 2, "u16"),
        ("Max age", 2, "u16"),
        ("Hello time", 2, "u16"),
        ("Forward delay", 2, "u16"),
        ("Unknown MAC discard", 1, "u8"),
        ("MAC learning depth", 1, "u8"),
        ("Dynamic filtering ageing", 4, "u32")
    ]),
    # 9.3.2 MAC bridge configuration data
    46: ("MAC bridge configuration data", [
        ("Bridge MAC address", 6, "hex"),
        ("Bridge priority", 2, "u16"),
        ("Designated root", 8, "hex"),
        ("Root path cost", 4, "u32"),
        ("Bridge port count", 1, "u8"),
        ("Root port num", 2, "u16"),
        ("Hello time", 2, "u16"),
        ("Forward delay", 2, "u16")
    ]),
    # 9.3.4 MAC bridge port configuration data
    47: ("MAC bridge port configuration data", [
        ("Bridge id pointer", 2, "hex"),
        ("Port num", 1, "u8"),
        ("TP type", 1, "u8"),
        ("TP pointer", 2, "hex"),
        ("Port priority", 2, "u16"),
        ("Port path cost", 2, "u16"),
        ("Port spanning tree ind", 1, "u8"),
        ("Encapsulation method", 1, "u8"),
        ("LAN FCS ind", 1, "u8"),
        ("Port MAC address", 6, "hex"),
        ("Outbound TD pointer", 2, "hex"),
        ("Inbound TD pointer", 2, "hex")
    ]),
    # 9.3.5 MAC bridge port designation data
    48: ("MAC bridge port designation data", [
        ("Designated bridge root cost port", 24, "hex"),
        ("Port state", 1, "u8")
    ]),
    # 9.3.6 MAC bridge port filter table data
    49: ("MAC bridge port filter table data", [
        ("MAC filter table", 8, "table")
    ]),
    # 9.3.8 MAC bridge port bridge table data
    50: ("MAC bridge port bridge table data", [
        ("Bridge table", 8, "table")
    ]),
    # 9.3.3 MAC bridge performance monitoring history data
    51: ("MAC Bridge PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Bridge learning entry discard count", 4, "u32")
    ]),
    # 9.3.9 MAC bridge port performance monitoring history data
    52: ("MAC Bridge Port PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Forwarded frame counter", 4, "u32"),
        ("Delay exceeded discard counter", 4, "u32"),
        ("MTU exceeded discard counter", 4, "u32"),
        ("Received frame counter", 4, "u32"),
        ("Received and discarded counter", 4, "u32")
    ]),
    # 9.9.1 Physical path termination point POTS UNI
    53: ("PPTP POTS UNI", [
        ("Administrative state", 1, "u8"),
        ("Deprecated", 2, "hex"),
        ("ARC", 1, "u8"),
        ("ARC interval", 1, "u8"),
        ("Impedance", 1, "u8"),
        ("Transmission path", 1, "u8"),
        ("Rx gain", 1, "u8"),
        ("Tx gain", 1, "u8"),
        ("Operational state", 1, "u8"),
        ("Hook state", 1, "u8"),
        ("POTS holdover time", 2, "u16")
    ]),
    # 9.9.6 Voice service profile
    58: ("Voice service profile", [
        ("Announcement type", 1, "u8"),
        ("Jitter target", 2, "u16"),
        ("Jitter buffer max", 2, "u16"),
        ("Echo cancel ind", 1, "u8"),
        ("PSTN protocol variant", 2, "u16"),
        ("DTMF digit levels", 2, "u16"),
        ("DTMF digit duration", 2, "u16"),
        ("Hook flash minimum time", 2, "u16"),
        ("Hook flash maximum time", 2, "u16"),
        ("Tone pattern table", 20, "table"),
        ("Tone event table", 7, "table"),
        ("Ringing pattern table", 5, "table"),
        ("Ringing event table", 7, "table")
    ]),
    # 9.3.12 VLAN tagging operation configuration data
    78: ("VLAN tagging operation config", [
        ("Upstream VLAN tagging mode", 1, "u8"),
        ("Upstream VLAN tag TCI value", 2, "u16"),
        ("Downstream VLAN tagging mode", 1, "u8"),
        ("Association type", 1, "u8"),
        ("Associated ME pointer", 2, "hex")
    ]),
    # 9.3.7 MAC bridge port filter pre-assign table
    79: ("MAC bridge port filter preassign table", [
        ("IPv4 multicast filtering", 1, "u8"),
        ("IPv6 multicast filtering", 1, "u8"),
        ("IPv4 broadcast filtering", 1, "u8"),
        ("RARP filtering", 1, "u8"),
        ("IPX filtering", 1, "u8"),
        ("NetBEUI filtering", 1, "u8"),
        ("AppleTalk filtering", 1, "u8"),
        ("Bridge management information filtering", 1, "u8"),
        ("ARP filtering", 1, "u8")
    ]),
    # 9.13.1 Physical path termination point video UNI
    82: ("PPTP Video UNI", [
        ("Administrative State", 1, "u8"),
        ("Operational State", 1, "u8"),
        ("ARC", 1, "u8"),
        ("ARC Interval", 1, "u8"),
        ("Power Control", 1, "u8")
    ]),
    # 9.3.11 VLAN tagging filter data
    84: ("VLAN tagging filter data", [
        ("VLAN filter list", 24, "hex"),
        ("Forward operation", 1, "u8"),
        ("Number of entries", 1, "u8")
    ]),
    # 9.5.3 Ethernet performance monitoring history data 2
    89: ("Ethernet PM History Data 2", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("PPPoE filtered frame counter", 4, "u32")
    ]),
    # 9.13.2 Physical path termination point video ANI
    90: ("PPTP Video ANI", [
        ("Administrative State", 1, "u8"),
        ("Operational State", 1, "u8"),
        ("ARC", 1, "u8"),
        ("ARC Interval", 1, "u8"),
        ("Frequency Range Low", 1, "u8"),
        ("Frequency Range High", 1, "u8"),
        ("Signal Capability", 1, "u8"),
        ("Optical Signal Level", 1, "u8"),
        ("Pilot Signal Level", 1, "u8"),
        ("Signal Level min", 1, "u8"),
        ("Signal Level max", 1, "u8"),
        ("Pilot Frequency", 4, "u32"),
        ("AGC Mode", 1, "u8"),
        ("AGC Setting", 1, "u8"),
        ("Video Lower Optical Threshold", 1, "u8"),
        ("Video Upper Optical Threshold", 1, "u8")
    ]),
    # 9.3.10 IEEE 802.1p mapper service profile
    130: ("802.1p Mapper Service Profile", [
        ("TP pointer", 2, "hex"),
        ("Interwork TP pointer P0", 2, "hex"),
        ("Interwork TP pointer P1", 2, "hex"),
        ("Interwork TP pointer P2", 2, "hex"),
        ("Interwork TP pointer P3", 2, "hex"),
        ("Interwork TP pointer P4", 2, "hex"),
        ("Interwork TP pointer P5", 2, "hex"),
        ("Interwork TP pointer P6", 2, "hex"),
        ("Interwork TP pointer P7", 2, "hex"),
        ("Unmarked frame option", 1, "u8"),
        ("DSCP to P-bit mapping", 24, "hex"),
        ("Default P-bit marking", 1, "u8"),
        ("TP Type", 1, "u8")
    ]),
    # 9.12.2 OLT-G
    131: ("OLT-G", [
        ("OLT vendor id", 4, "str"),
        ("Equipment id", 20, "str"),
        ("OLT version", 14, "str")
    ]),
    # 9.1.7 ONU power shedding
    133: ("ONU Power Shedding", [
        ("Restore power timer reset interval", 2, "u16"),
        ("Data class shedding interval", 2, "u16"),
        ("Voice class shedding interval", 2, "u16"),
        ("Video overlay class shedding interval", 2, "u16"),
        ("Video return class shedding interval", 2, "u16"),
        ("DSL class shedding interval", 2, "u16"),
        ("ATM class shedding interval", 2, "u16"),
        ("CES class shedding interval", 2, "u16"),
        ("Frame class shedding interval", 2, "u16"),
        ("SONET class shedding interval", 2, "u16"),
        ("Shedding status", 2, "hex")
    ]),
    # 9.4.1 IP host config data
    134: ("IP Host Config Data", [
        ("IP options", 1, "u8"),
        ("MAC address", 6, "hex"),
        ("Onu identifier", 25, "str"),
        ("IP address", 4, "u32"),
        ("Mask", 4, "u32"),
        ("Gateway", 4, "u32"),
        ("Primary DNS", 4, "u32"),
        ("Secondary DNS", 4, "u32"),
        ("Current address", 4, "u32"),
        ("Current mask", 4, "u32"),
        ("Current gateway", 4, "u32"),
        ("Current primary DNS", 4, "u32"),
        ("Current secondary DNS", 4, "u32"),
        ("Domain name", 25, "str"),
        ("Host name", 25, "str")
    ]),
    # 9.4.2 IP host performance monitoring history data
    135: ("IP Host PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("ICMP errors", 4, "u32"),
        ("DNS errors", 4, "u32"),
        ("DHCP timeouts", 2, "u16"),
        ("IP address conflict", 2, "u16"),
        ("Out of memory", 2, "u16"),
        ("Internal error", 2, "u16")
    ]),
    # 9.4.3 TCP/UDP config data
    136: ("TCP/UDP Config Data", [
        ("Port id", 2, "u16"),
        ("Protocol", 1, "u8"),
        ("TOS/diffserv field", 1, "u8"),
        ("IP host pointer", 2, "hex")
    ]),
    # 9.12.3 Network address
    137: ("Network Address", [
        ("Security pointer", 2, "hex"),
        ("Address pointer", 2, "hex")
    ]),
    # 9.9.18 VoIP config data
    138: ("VoIP Config Data", [
        ("Available signalling protocols", 1, "u8"),
        ("Signalling protocol used", 1, "u8"),
        ("Available VoIP configuration methods", 4, "hex"),
        ("VoIP configuration method used", 1, "u8"),
        ("VoIP configuration address pointer", 2, "hex"),
        ("VoIP configuration state", 1, "u8"),
        ("Retrieve profile", 1, "u8"),
        ("Profile version", 25, "str")
    ]),
    # 9.9.4 VoIP voice CTP
    139: ("VoIP Voice CTP", [
        ("User protocol pointer", 2, "hex"),
        ("PPTP pointer", 2, "hex"),
        ("VoIP media profile pointer", 2, "hex"),
        ("Signalling code", 1, "u8")
    ]),
    # 9.9.12 Call control PM history data
    140: ("Call Control PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Call setup failures", 4, "u32"),
        ("Call setup timer", 4, "u32"),
        ("Call terminate failures", 4, "u32"),
        ("Analog port releases", 4, "u32"),
        ("Analog port off-hook timer", 4, "u32")
    ]),
    # 9.9.11 VoIP line status
    141: ("VoIP Line Status", [
        ("Voip codec used", 2, "u16"),
        ("Voip voice server status", 1, "u8"),
        ("Voip port session type", 1, "u8"),
        ("Voip call 1 packet period", 2, "u16"),
        ("Voip call 2 packet period", 2, "u16"),
        ("Voip call 1 dest addr", 25, "str"),
        ("Voip call 2 dest addr", 25, "str")
    ]),
    # 9.9.5 VoIP media profile
    142: ("VoIP Media Profile", [
        ("Fax mode", 1, "u8"),
        ("Voice service profile pointer", 2, "hex"),
        ("Codec selection 1st", 1, "u8"),
        ("Packet period selection 1st", 1, "u8"),
        ("Silence suppression 1st", 1, "u8"),
        ("Codec selection 2nd", 1, "u8"),
        ("Packet period selection 2nd", 1, "u8"),
        ("Silence suppression 2nd", 1, "u8"),
        ("Codec selection 3rd", 1, "u8"),
        ("Packet period selection 3rd", 1, "u8"),
        ("Silence suppression 3rd", 1, "u8"),
        ("Codec selection 4th", 1, "u8"),
        ("Packet period selection 4th", 1, "u8"),
        ("Silence suppression 4th", 1, "u8"),
        ("OOB DTMF", 1, "u8"),
        ("RTP profile pointer", 2, "hex")
    ]),
    # 9.9.7 RTP profile data
    143: ("RTP Profile Data", [
        ("Local port min", 2, "u16"),
        ("Local port max", 2, "u16"),
        ("DSCP mark", 1, "u8"),
        ("Piggyback events", 1, "u8"),
        ("Tone events", 1, "u8"),
        ("DTMF events", 1, "u8"),
        ("CAS events", 1, "u8")
    ]),
    # 9.9.13 RTP PM history data
    144: ("RTP PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("RTP errors", 4, "u32"),
        ("Packet loss", 4, "u32"),
        ("Maximum jitter", 4, "u32"),
        ("Max time between RTCP", 4, "u32"),
        ("Buffer underflows", 4, "u32"),
        ("Buffer overflows", 4, "u32")
    ]),
    # 9.9.10 Network dial plan table
    145: ("Network Dial Plan Table", [
        ("Dial plan number", 2, "u16"),
        ("Dial plan table max size", 2, "u16"),
        ("Critical dial timeout", 2, "u16"),
        ("Partial dial timeout", 2, "u16"),
        ("Dial plan format", 1, "u8"),
        ("Dial plan table", 30, "table")
    ]),
    # 9.9.8 VoIP application service profile
    146: ("VoIP App Service Profile", [
        ("CID features", 1, "u8"),
        ("Call waiting features", 1, "u8"),
        ("Call progress transfer", 2, "u16"),
        ("Call presentation", 2, "u16"),
        ("Direct connect feature", 1, "u8"),
        ("Direct connect URI ptr", 2, "hex"),
        ("Bridged line agent URI ptr", 2, "hex"),
        ("Conference factory URI ptr", 2, "hex")
    ]),
    # 9.9.9 VoIP feature access codes
    147: ("VoIP Feature Access Codes", [
        ("Cancel call waiting", 5, "str"),
        ("Call hold", 5, "str"),
        ("Call park", 5, "str"),
        ("Caller ID activate", 5, "str"),
        ("Caller ID deactivate", 5, "str"),
        ("Do not disturb activation", 5, "str"),
        ("Do not disturb deactivation", 5, "str"),
        ("Do not disturb PIN change", 5, "str"),
        ("Emergency service number", 5, "str"),
        ("Intercom service", 5, "str"),
        ("Unattended call transfer", 5, "str"),
        ("Attended call transfer", 5, "str")
    ]),
    # 9.12.4 Authentication security method
    148: ("Authentication Security Method", [
        ("Validation scheme", 1, "u8"),
        ("Username 1", 25, "str"),
        ("Password", 25, "str"),
        ("Realm", 25, "str"),
        ("Username 2", 25, "str")
    ]),
    # 9.9.19 SIP config portal
    149: ("SIP Config Portal", [
        ("Configuration text table", 1, "table")
    ]),
    # 9.9.3 SIP agent config data
    150: ("SIP Agent Config Data", [
        ("Proxy server addr ptr", 2, "hex"),
        ("Outbound proxy addr ptr", 2, "hex"),
        ("SIP registrar addr ptr", 2, "hex"),
        ("SIP softswitch", 25, "str"),
        ("SIP port", 2, "u16"),
        ("SIP expiry time", 4, "u32"),
        ("SIP registration exp time", 1, "u8"),
        ("SIP retry guard timer", 2, "u16"),
        ("SIP retry max count", 2, "u16"),
        ("SIP timer T1", 2, "u16"),
        ("SIP timer T2", 2, "u16"),
        ("SIP timer T4", 2, "u16"),
        ("SIP timer D", 2, "u16"),
        ("SIP event subscribe", 1, "u8")
    ]),
    # 9.9.14 SIP agent PM history data
    151: ("SIP Agent PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("SIP invite requests", 4, "u32"),
        ("SIP invite retries", 4, "u32"),
        ("SIP invite failures", 4, "u32"),
        ("SIP register requests", 4, "u32"),
        ("SIP register retries", 4, "u32"),
        ("SIP register failures", 4, "u32"),
        ("SIP bye requests", 4, "u32"),
        ("SIP bye failures", 4, "u32"),
        ("SIP cancel requests", 4, "u32"),
        ("SIP cancel failures", 4, "u32"),
        ("SIP info requests", 4, "u32"),
        ("SIP info failures", 4, "u32")
    ]),
    # 9.9.15 SIP call initiation PM history data
    152: ("SIP Call Initiation PM", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Inbound ok", 4, "u32"),
        ("Inbound failed", 4, "u32"),
        ("Outbound ok", 4, "u32"),
        ("Outbound failed", 4, "u32"),
        ("Inbound connect time", 4, "u32"),
        ("Outbound connect time", 4, "u32")
    ]),
    # 9.9.2 SIP user data
    153: ("SIP User Data", [
        ("SIP agent config ptr", 2, "hex"),
        ("User name", 25, "str"),
        ("Password", 25, "str"),
        ("User part AOR", 25, "str"),
        ("Feature set ptr", 2, "hex"),
        ("PPS timer", 1, "u8")
    ]),
    # 9.9.20 MGC config portal
    154: ("MGC Config Portal", [
        ("Configuration text table", 1, "table")
    ]),
    # 9.9.16 MGC config data
    155: ("MGC Config Data", [
        ("MGC 1", 2, "hex"),
        ("MGC 2", 2, "hex"),
        ("MGC 3", 2, "hex"),
        ("MGC 4", 2, "hex"),
        ("Registration expiry time", 2, "u16"),
        ("MGC 1 IP addr ptr", 2, "hex"),
        ("MGC 2 IP addr ptr", 2, "hex"),
        ("MGC 3 IP addr ptr", 2, "hex"),
        ("MGC 4 IP addr ptr", 2, "hex"),
        ("Message header", 1, "u8"),
        ("Termination id prefix", 25, "str"),
        ("Termination id base", 4, "u32")
    ]),
    # 9.9.17 MGC PM history data
    156: ("MGC PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Transaction failures", 4, "u32")
    ]),
    # 9.12.5 Large string
    157: ("Large String", [
        ("Number of parts", 1, "u8"),
        ("String part 1", 25, "str"),
        ("String part 2", 25, "str"),
        ("String part 3", 25, "str"),
        ("String part 4", 25, "str"),
        ("String part 5", 25, "str"),
        ("String part 6", 25, "str"),
        ("String part 7", 25, "str"),
        ("String part 8", 25, "str"),
        ("String part 9", 25, "str"),
        ("String part 10", 25, "str"),
        ("String part 11", 25, "str"),
        ("String part 12", 25, "str"),
        ("String part 13", 25, "str"),
        ("String part 14", 25, "str"),
        ("String part 15", 25, "str")
    ]),
    # 9.1.12 ONU remote debug
    158: ("ONT Remote Debug", [
        ("Command", 1, "u8"),
        ("Command table", 1, "table"),
        ("Reply table", 1, "table")
    ]),
    # 9.1.11 Equipment protection profile
    159: ("Equipment protection profile", [
        ("Protection type", 1, "u8"),
        ("Wait to restore time", 2, "u16")
    ]),
    # 9.1.9 Equipment extension package
    160: ("Equipment extension package", [
        ("Vendor-specific extension", 1, "table")
    ]),
    # 9.3.13 Extended VLAN tagging operation configuration data
    171: ("Extended VLAN tagging operation configuration data", [
        ("Association type", 1, "u8"),
        ("Received frame VLAN tagging operation table max size", 2, "u16"),
        ("Input TPID", 2, "hex"),
        ("Output TPID", 2, "hex"),
        ("Downstream mode", 1, "u8"),
        ("Received frame VLAN tagging operation table", 16, "table"),
        ("Associated ME pointer", 2, "hex"),
        ("DSCP to P-bit mapping", 24, "hex")
    ]),
    # 9.1.1 ONU-G
    256: ("ONT-G", [
        ("Vendor ID", 4, "str"),
        ("Version", 14, "str"),
        ("Serial number", 8, "hex"),
        ("Traffic management option", 1, "u8"),
        ("Deprecated 1", 1, "u8"),
        ("Battery backup", 1, "u8"),
        ("Administrative state", 1, "u8"),
        ("Operational state", 1, "u8"),
        ("ONU survival time", 1, "u8"),
        ("Logical ONU ID", 10, "str"),
        ("Logical password", 10, "str"),
        ("Credentials flags", 1, "u8")
    ]),
    # 9.1.2 ONU2-G
    257: ("ONT2-G", [
        ("Equipment ID", 20, "str"),
        ("OMCC version", 1, "u8"),
        ("Vendor product code", 2, "u16"),
        ("Security capability", 1, "u8"),
        ("Security mode", 1, "u8"),
        ("Total priority queue number", 2, "u16"),
        ("Total traffic scheduler number", 1, "u8"),
        ("Deprecated 1", 1, "u8"),
        ("Total GEM port id number", 2, "u16"),
        ("SysUpTime", 4, "u32"),
        ("Connectivity capability", 2, "hex"),
        ("Current connectivity mode", 1, "u8")
    ]),
    # 9.2.2 T-CONT
    262: ("T-CONT", [
        ("Alloc-ID", 2, "u16"),
        ("Deprecated 1", 1, "u8"),
        ("Policy", 1, "u8")
    ]),
    # 9.2.1 ANI-G
    263: ("ANI-G", [
        ("SR indication", 1, "u8"),
        ("Total T-CONT number", 2, "u16"),
        ("GEM block length", 2, "u16"),
        ("Piggyback DBA reporting", 1, "u8"),
        ("Whole ONT DBA reporting", 1, "u8"),
        ("SF threshold", 1, "u8"),
        ("SD threshold", 1, "u8"),
        ("ARC", 1, "u8"),
        ("ARC interval", 1, "u8"),
        ("Optical signal level", 2, "u16"),
        ("Lower optical threshold", 1, "u8"),
        ("Upper optical threshold", 1, "u8"),
        ("ONT response time", 2, "u16"),
        ("Transmit optical level", 2, "u16"),
        ("Lower transmit threshold", 1, "u8"),
        ("Upper transmit threshold", 1, "u8")
    ]),
    # 9.12.1 UNI-G
    264: ("UNI-G", [
        ("Administrative state", 1, "u8"),
        ("Operational state", 1, "u8"),
        ("ARC", 1, "u8"),
        ("ARC interval", 1, "u8"),
        ("Management capability", 1, "u8"),
        ("Non-OMCI management identifier", 2, "u16"),
        ("Configality ind", 1, "u8"),
        ("Relay agent options", 2, "hex")
    ]),
    # 9.2.4 GEM interworking Termination Point
    266: ("GEM interworking Termination Point", [
        ("GEM port network CTP pointer", 2, "hex"),
        ("Interworking option", 1, "u8"),
        ("Service profile pointer", 2, "hex"),
        ("Interworking termination point pointer", 2, "hex"),
        ("PPTP counter", 1, "u8"),
        ("Operational state", 1, "u8"),
        ("GAL profile pointer", 2, "hex"),
        ("GAL loopback configuration", 1, "u8")
    ]),
    # 9.2.13 GEM Port PM History Data
    267: ("GEM Port PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Transmitted GEM frames", 4, "u32"),
        ("Received GEM frames", 4, "u32"),
        ("Received payload bytes", 8, "u64"),
        ("Transmitted payload bytes", 8, "u64"),
        ("Encryption key errors", 4, "u32")
    ]),
    # 9.2.3 GEM Port Network CTP
    268: ("GEM Port Network CTP", [
        ("Port-ID", 2, "u16"),
        ("T-CONT pointer", 2, "hex"),
        ("Direction", 1, "u8"),
        ("Traffic management pointer upstream", 2, "hex"),
        ("Traffic descriptor profile pointer", 2, "hex"),
        ("UNI counter", 1, "u8"),
        ("Priority queue pointer downstream", 2, "hex"),
        ("Encryption state", 1, "u8")
    ]),
    # 9.2.7 GAL TDM profile
    271: ("GAL TDM profile", [
        ("Entity ID", 2, "hex"),
        ("GAL loopback configuration", 1, "u8")
    ]),
    # 9.2.6 GAL Ethernet profile
    272: ("GAL Ethernet profile", [
        ("Maximum GEM payload size", 2, "u16")
    ]),
    # 9.12.6 Threshold Data 1
    273: ("Threshold Data 1", [
        ("Threshold value 1", 4, "u32"),
        ("Threshold value 2", 4, "u32"),
        ("Threshold value 3", 4, "u32"),
        ("Threshold value 4", 4, "u32"),
        ("Threshold value 5", 4, "u32"),
        ("Threshold value 6", 4, "u32"),
        ("Threshold value 7", 4, "u32")
    ]),
    # 9.12.7 Threshold Data 2
    274: ("Threshold Data 2", [
        ("Threshold value 1", 4, "u32"),
        ("Threshold value 2", 4, "u32"),
        ("Threshold value 3", 4, "u32"),
        ("Threshold value 4", 4, "u32"),
        ("Threshold value 5", 4, "u32"),
        ("Threshold value 6", 4, "u32"),
        ("Threshold value 7", 4, "u32")
    ]),
    # 9.2.16 GAL TDM PM History Data
    275: ("GAL TDM PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Discarded octets", 4, "u32")
    ]),
    # 9.2.8 GAL Ethernet PM History Data
    276: ("GAL Ethernet PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Discarded frames", 4, "u32")
    ]),
    # 9.2.10 Priority queue-G
    277: ("Priority queue-G", [
        ("Queue configuration option", 1, "u8"),
        ("Maximum queue size", 2, "u16"),
        ("Allocated queue size", 2, "u16"),
        ("Discard-block reset interval", 2, "u16"),
        ("Threshold value for discarded blocks", 2, "u16"),
        ("Related port", 4, "hex"),
        ("Traffic scheduler pointer", 2, "hex"),
        ("Weight", 1, "u8"),
        ("Back-pressure operation", 2, "u16"),
        ("Back-pressure time", 4, "u32"),
        ("Back-pressure occur counter", 2, "u16"),
        ("Back-pressure clear counter", 2, "u16")
    ]),
    # 9.2.11 Traffic Scheduler-G
    278: ("Traffic Scheduler-G", [
        ("T-CONT pointer", 2, "hex"),
        ("Traffic scheduler pointer", 2, "hex"),
        ("Policy", 1, "u8"),
        ("Priority/Weight", 1, "u8")
    ]),
    # 9.1.10 Protection data
    279: ("Protection data", [
        ("Protection table", 1, "table")
    ]),
    # 9.2.12 Traffic descriptor
    280: ("Traffic descriptor", [
        ("CIR", 4, "u32"),
        ("PIR", 4, "u32"),
        ("CBS", 4, "u32"),
        ("PBS", 4, "u32"),
        ("Colour mode", 1, "u8"),
        ("Ingress colour marking", 1, "u8"),
        ("Egress colour marking", 1, "u8"),
        ("Meter type", 1, "u8")
    ]),
    # 9.2.5 Multicast GEM interworking termination point
    281: ("Multicast GEM interworking termination point", [
        ("GEM port network CTP pointer", 2, "hex"),
        ("Interworking option", 1, "u8"),
        ("Service profile pointer", 2, "hex"),
        ("Interworking termination point pointer", 2, "hex"),
        ("PPTP counter", 1, "u8"),
        ("Operational state", 1, "u8"),
        ("GAL profile pointer", 2, "hex"),
        ("GAL loopback configuration", 1, "u8"),
        ("Multicast address table", 12, "table")
    ]),
    # 9.12.8 OMCI
    287: ("OMCI", [
        ("OMCI ME type table", 2, "table"),
        ("OMCI message type table", 1, "table")
    ]),
    # 9.12.9 Managed entity
    288: ("Managed entity", [
        ("Name", 25, "str"),
        ("Attributes table", 2, "table"),
        ("Access", 1, "u8"),
        ("Alarms table", 1, "table"),
        ("AVCs table", 1, "table"),
        ("Actions", 4, "hex"),
        ("Instances table", 2, "table"),
        ("Support", 1, "u8")
    ]),
    # 9.12.10 Attribute
    289: ("Attribute", [
        ("Name", 25, "str"),
        ("Size", 2, "u16"),
        ("Access", 1, "u8"),
        ("Format", 1, "u8"),
        ("Lower bound", 4, "u32"),
        ("Upper bound", 4, "u32"),
        ("Bit field mask", 4, "hex"),
        ("Code table", 2, "table"),
        ("Support", 1, "u8")
    ]),
    # 9.3.14 Dot1X Port Extension Package
    290: ("Dot1X Port Extension Package", [
        ("Dot1X enable", 1, "u8"),
        ("Authenticator PAE control", 1, "u8"),
        ("Authenticator PAE state", 1, "u8"),
        ("Backend authentication state", 1, "u8"),
        ("Admin controlled directions", 1, "u8"),
        ("Operational controlled directions", 1, "u8"),
        ("Authenticator PAE capabilities", 1, "u8"),
        ("Quiet period", 2, "u16"),
        ("Server timeout", 2, "u16"),
        ("Supplicant timeout", 2, "u16"),
        ("Re-authentication period", 4, "u32"),
        ("Re-authentication enable", 1, "u8"),
        ("Key transmission enable", 1, "u8")
    ]),
    # 9.3.15 Dot1X configuration profile
    291: ("Dot1X configuration profile", [
        ("Domain name prefix", 2, "hex"),
        ("Radius fallback enable", 1, "u8"),
        ("Radius server IP address pointer", 2, "hex"),
        ("Shared secret pointer", 2, "hex")
    ]),
    # 9.3.16 Dot1X performance monitoring history data
    292: ("Dot1X performance monitoring history data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("EAPOL frames transmitted", 4, "u32"),
        ("EAPOL frames received", 4, "u32"),
        ("EAPOL start frames received", 4, "u32"),
        ("EAPOL logoff frames received", 4, "u32"),
        ("EAP resp/id frames received", 4, "u32"),
        ("EAP response frames received", 4, "u32"),
        ("EAP req/id frames transmitted", 4, "u32"),
        ("EAP request frames transmitted", 4, "u32"),
        ("Invalid EAPOL frames received", 4, "u32"),
        ("EAP length error frames received", 4, "u32"),
        ("Last EAPOL frame version received", 1, "u8"),
        ("Last EAPOL frame source address received", 6, "hex")
    ]),
    # 9.3.17 Radius performance monitoring history data
    293: ("Radius performance monitoring history data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Access request packets transmitted", 4, "u32"),
        ("Access request retransmissions", 4, "u32"),
        ("Access accept packets received", 4, "u32"),
        ("Access reject packets received", 4, "u32"),
        ("Access challenge packets received", 4, "u32"),
        ("Malformed packets received", 4, "u32"),
        ("Bad authenticators received", 4, "u32"),
        ("Packets dropped", 4, "u32"),
        ("Timeouts", 4, "u32")
    ]),
    # 9.5.4 Ethernet PM History Data 3
    296: ("Ethernet PM History Data 3", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Drop events", 4, "u32"),
        ("Octets", 4, "u32"),
        ("Packets", 4, "u32"),
        ("Broadcast packets", 4, "u32"),
        ("Multicast packets", 4, "u32"),
        ("Undersize packets", 4, "u32"),
        ("Fragments", 4, "u32"),
        ("Jabbers", 4, "u32"),
        ("64 octets", 4, "u32"),
        ("65-127 octets", 4, "u32"),
        ("128-255 octets", 4, "u32"),
        ("256-511 octets", 4, "u32"),
        ("512-1023 octets", 4, "u32"),
        ("1024-1518 octets", 4, "u32")
    ]),
    # 9.1.8 Port mapping package
    297: ("Port mapping package", [
        ("Port mapping table", 1, "table")
    ]),
    # 9.3.18 Dot1 rate limiter
    298: ("Dot1 rate limiter", [
        ("Rate limiter configuration table", 2, "table")
    ]),
    # 9.3.19 Dot1ag maintenance domain
    299: ("Dot1ag maintenance domain", [
        ("MD level", 1, "u8"),
        ("MD name format", 1, "u8"),
        ("MD name", 25, "str"),
        ("Maintenance intermediate point", 1, "u8"),
        ("Sender ID permission", 1, "u8")
    ]),
    # 9.3.20 Dot1ag maintenance association
    300: ("Dot1ag maintenance association", [
        ("MD pointer", 2, "hex"),
        ("Short MA name format", 1, "u8"),
        ("Short MA name", 25, "str"),
        ("Continuity check message interval", 1, "u8"),
        ("Associated VLANs", 24, "hex"),
        ("MHF creation", 1, "u8"),
        ("Sender ID permission", 1, "u8")
    ]),
    # 9.3.21 Dot1ag default MD level
    301: ("Dot1ag default MD level", [
        ("Layer 2 pointer", 2, "hex"),
        ("Layer 2 type", 1, "u8"),
        ("Default MD level", 1, "u8"),
        ("Primary VLAN", 2, "u16"),
        ("Status", 1, "u8")
    ]),
    # 9.3.22 Dot1ag MEP
    302: ("Dot1ag MEP", [
        ("Layer 2 pointer", 2, "hex"),
        ("Layer 2 type", 1, "u8"),
        ("MA pointer", 2, "hex"),
        ("MEP ID", 2, "u16"),
        ("MEP control", 1, "u8"),
        ("Primary VLAN", 2, "u16"),
        ("Administrative state", 1, "u8"),
        ("CCM LTM priority", 1, "u8"),
        ("Egress identifier", 8, "hex")
    ]),
    # 9.3.23 Dot1ag MEP status
    303: ("Dot1ag MEP status", [
        ("Operational state", 1, "u8"),
        ("FNG state", 1, "u8"),
        ("Highest priority defect", 1, "u8"),
        ("Defect flags", 1, "u8"),
        ("Last RDI", 1, "u8"),
        ("Port status", 1, "u8"),
        ("Interface status", 1, "u8"),
        ("Active remote MEPs table", 2, "table")
    ]),
    # 9.3.24 Dot1ag MEP CCM database
    304: ("Dot1ag MEP CCM database", [
        ("MEP CCM database table", 2, "table")
    ]),
    # 9.3.25 Dot1ag CFM stack
    305: ("Dot1ag CFM stack", [
        ("CFM stack table", 2, "table")
    ]),
    # 9.3.26 Dot1ag chassis-management info
    306: ("Dot1ag chassis-management info", [
        ("Chassis ID length", 1, "u8"),
        ("Chassis ID sub-type", 1, "u8"),
        ("Chassis ID", 25, "str"),
        ("Management address table", 2, "table")
    ]),
    # 9.12.11 Octet string
    307: ("Octet string", [
        ("Octet string", 25, "hex")
    ]),
    # 9.12.12 General purpose buffer
    308: ("General purpose buffer", [
        ("Buffer table", 1, "table")
    ]),
    # 9.3.27 Multicast operations profile
    309: ("Multicast operations profile", [
        ("IGMP version", 1, "u8"),
        ("IGMP function", 1, "u8"),
        ("Immediate leave", 1, "u8"),
        ("Upstream IGMP TCI", 2, "u16"),
        ("Upstream IGMP tag control", 1, "u8"),
        ("Upstream IGMP rate", 4, "u32"),
        ("Dynamic access control list table", 24, "table"),
        ("Static access control list table", 24, "table"),
        ("Lost groups list table", 10, "table"),
        ("Robustness", 1, "u8"),
        ("Querier IP address", 4, "u32"),
        ("Query interval", 4, "u32"),
        ("Query max response time", 4, "u32"),
        ("Last member query interval", 4, "u32"),
        ("Unauthorized join behaviour", 1, "u8"),
        ("Downstream IGMP TCI", 2, "u16")
    ]),
    # 9.3.28 Multicast subscriber config info
    310: ("Multicast subscriber config info", [
        ("ME ID pointer", 2, "hex"),
        ("Multicast operations profile pointer", 2, "hex"),
        ("Max simultaneous groups", 2, "u16"),
        ("Max multicast bandwidth", 4, "u32"),
        ("Bandwidth enforcement", 1, "u8"),
        ("Multicast service package table", 20, "table"),
        ("Allowed preview groups table", 22, "table")
    ]),
    # 9.3.29 Multicast Subscriber Monitor
    311: ("Multicast Subscriber Monitor", [
        ("ME ID pointer", 2, "hex"),
        ("Number of joined groups", 2, "u16"),
        ("Active groups table", 25, "table")
    ]),
    # 9.2.9 FEC PM History Data
    312: ("FEC PM History Data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Corrected bytes", 4, "u32"),
        ("Corrected code words", 4, "u32"),
        ("Uncorrectable code words", 4, "u32"),
        ("Total code words", 4, "u32"),
        ("FEC seconds", 2, "u16")
    ]),
    # 9.12.13 File transfer controller
    318: ("File transfer controller", [
        ("File name", 25, "str"),
        ("Local file name", 25, "str"),
        ("File size", 4, "u32"),
        ("File transfer options", 1, "u8"),
        ("Window size", 2, "u16"),
        ("Timeout", 2, "u16"),
        ("File transfer status", 1, "u8"),
        ("File transfer table", 1, "table")
    ]),
    # 9.3.31 Ethernet frame PM History Data DS
    321: ("Ethernet Frame PM History Data DS", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Drop events", 4, "u32"),
        ("Octets", 4, "u32"),
        ("Packets", 4, "u32"),
        ("Broadcast packets", 4, "u32"),
        ("Multicast packets", 4, "u32"),
        ("CRC errored packets", 4, "u32"),
        ("Undersize packets", 4, "u32"),
        ("Oversize packets", 4, "u32"),
        ("64 octets", 4, "u32"),
        ("65-127 octets", 4, "u32"),
        ("128-255 octets", 4, "u32"),
        ("256-511 octets", 4, "u32"),
        ("512-1023 octets", 4, "u32"),
        ("1024-1518 octets", 4, "u32")
    ]),
    # 9.3.30 Ethernet frame PM History Data US
    322: ("Ethernet Frame PM History Data US", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Drop events", 4, "u32"),
        ("Octets", 4, "u32"),
        ("Packets", 4, "u32"),
        ("Broadcast packets", 4, "u32"),
        ("Multicast packets", 4, "u32"),
        ("CRC errored packets", 4, "u32"),
        ("Undersize packets", 4, "u32"),
        ("Oversize packets", 4, "u32"),
        ("64 octets", 4, "u32"),
        ("65-127 octets", 4, "u32"),
        ("128-255 octets", 4, "u32"),
        ("256-511 octets", 4, "u32"),
        ("512-1023 octets", 4, "u32"),
        ("1024-1518 octets", 4, "u32")
    ]),
    # 9.5.5 Virtual Ethernet interface point
    329: ("Virtual Ethernet interface point", [
        ("Administrative state", 1, "u8"),
        ("Operational state", 1, "u8"),
        ("Interwork termination point pointer", 2, "hex"),
        ("IANA assigned port", 2, "u16")
    ]),
    # 9.12.14 Generic status portal
    330: ("Generic status portal", [
        ("Status document table", 1, "table")
    ]),
    # 9.1.13 ONU-E
    331: ("ONU-E", [
        ("Vendor ID", 4, "str"),
        ("Version", 14, "str"),
        ("Serial number", 8, "hex"),
        ("Administrative state", 1, "u8"),
        ("Operational state", 1, "u8"),
        ("ONU survival time", 1, "u8")
    ]),
    # 9.13.11 Enhanced security control
    332: ("Enhanced security control", [
        ("OLT crypto capabilities table", 1, "table"),
        ("OLT random challenge table", 1, "table"),
        ("OLT call back table", 1, "table"),
        ("Authentication state", 1, "u8"),
        ("ONU selected crypto capabilities", 1, "u8"),
        ("ONU random challenge table", 1, "table"),
        ("ONU authentication response table", 1, "table"),
        ("Master session key name table", 1, "table"),
        ("Broadcast key table", 1, "table"),
        ("Effective key length", 2, "u16")
    ]),
    # 9.3.32 Ethernet frame extended PM
    334: ("Ethernet frame extended PM", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Control block", 16, "hex"),
        ("Drop events", 4, "u32"),
        ("Octets", 4, "u32"),
        ("Frames", 4, "u32"),
        ("Broadcast frames", 4, "u32"),
        ("Multicast frames", 4, "u32"),
        ("CRC errored frames", 4, "u32"),
        ("Undersize frames", 4, "u32"),
        ("Oversize frames", 4, "u32"),
        ("64 octets", 4, "u32"),
        ("65-127 octets", 4, "u32"),
        ("128-255 octets", 4, "u32"),
        ("256-511 octets", 4, "u32"),
        ("512-1023 octets", 4, "u32"),
        ("1024-1518 octets", 4, "u32")
    ]),
    # 9.12.15 SNMP configuration data
    335: ("SNMP configuration data", [
        ("SNMP engine ID", 25, "str"),
        ("SNMP agent address pointer", 2, "hex"),
        ("SNMP community name", 25, "str"),
        ("SNMP trap destination address pointer", 2, "hex")
    ]),
    # 9.1.14 ONU dynamic power management control
    336: ("ONU dynamic power management control", [
        ("Power reduction management capability", 2, "hex"),
        ("Power reduction management mode", 1, "u8"),
        ("I-Shed timer", 2, "u16"),
        ("I-Sleep timer", 4, "u32"),
        ("I-Watch timer", 4, "u32"),
        ("Maximum sleep interval", 4, "u32"),
        ("Minimum active interval", 4, "u32")
    ]),
    # 9.12.16 TR-069 management server
    340: ("TR-069 management server", [
        ("Administrative state", 1, "u8"),
        ("ACS URL", 25, "str"),
        ("Username", 25, "str"),
        ("Password", 25, "str"),
        ("Periodic inform enable", 1, "u8"),
        ("Periodic inform interval", 4, "u32"),
        ("Connection request URL", 25, "str"),
        ("Connection request username", 25, "str"),
        ("Connection request password", 25, "str"),
        ("Associated IP host config ptr", 2, "hex")
    ]),
    # 9.3.12 MAC Bridge Port PM History Data
    341: ("GEM port network CTP performance monitoring history data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Transmitted GEM frames", 4, "u32"),
        ("Received GEM frames", 4, "u32"),
        ("Received payload bytes", 8, "u64"),
        ("Transmitted payload bytes", 8, "u64"),
        ("Encryption key errors", 4, "u32")
    ]),
    # 9.4.4 TCP/UDP performance monitoring history data
    342: ("TCP/UDP performance monitoring history data", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("TCP segments received", 4, "u32"),
        ("TCP segments sent", 4, "u32"),
        ("TCP errors", 4, "u32"),
        ("UDP datagrams received", 4, "u32"),
        ("UDP datagrams sent", 4, "u32"),
        ("UDP errors", 4, "u32")
    ]),
    # 9.3.34 Ethernet frame extended PM 64 bit
    425: ("Ethernet frame extended PM 64 bit", [
        ("Interval end time", 1, "u8"),
        ("Threshold data 1/2 id", 2, "hex"),
        ("Control block", 16, "hex"),
        ("Drop events", 8, "u64"),
        ("Octets", 8, "u64"),
        ("Frames", 8, "u64"),
        ("Broadcast frames", 8, "u64"),
        ("Multicast frames", 8, "u64"),
        ("CRC errored frames", 8, "u64"),
        ("Undersize frames", 8, "u64"),
        ("Oversize frames", 8, "u64"),
        ("64 octets", 8, "u64"),
        ("65-127 octets", 8, "u64"),
        ("128-255 octets", 8, "u64"),
        ("256-511 octets", 8, "u64"),
        ("512-1023 octets", 8, "u64"),
        ("1024-1518 octets", 8, "u64")
    ])
}

def get_me_name(class_id):
    if class_id in ME_CLASS_NAMES:
        return ME_CLASS_NAMES[class_id]
    if 172 <= class_id <= 239:
        return "Reserved for future B-PON managed entities"
    elif 240 <= class_id <= 255:
        return "Reserved for vendor-specific managed entities"
    elif 350 <= class_id <= 399:
        return "Reserved for vendor-specific use"
    elif 467 <= class_id <= 65279:
        return "Reserved for future standardization"
    elif 65280 <= class_id <= 65535:
        return "Reserved for vendor-specific use"
    else:
        return "None"

class MIBInstance:
    def __init__(self, class_id, inst_id):
        self.class_id = class_id
        self.inst_id = inst_id
        self.attributes = {}
        self.is_unknown = class_id not in ME_SPEC

        if not self.is_unknown:
            _, attr_defs = ME_SPEC[class_id]
            for name, _, _ in attr_defs:
                self.attributes[name] = 0
        else:
            self.vendor_data = [] # format [(mask, hex_data)]

    def update(self, mask, data):
        # unknown MEs
        if self.is_unknown:
            self.vendor_data.append((mask, data.hex().upper()))
            return
        # SPEC MEs
        me_name, attr_definitions = ME_SPEC[self.class_id]
        offset = 0
        for i, (attr_name, length, attr_type) in enumerate(attr_definitions):
            mask_bit = 1 << (15 - i)
            if mask & mask_bit:
                if offset + length > len(data):
                    break

                chunk = data[offset:offset+length]

                if attr_type == "u8":
                    val = chunk[0]
                elif attr_type == "u16":
                    val = struct.unpack(">H", chunk)[0]
                elif attr_type == "u32":
                    val = struct.unpack(">I", chunk)[0]
                elif attr_type == "str":
                    val = chunk.decode('ascii', errors='ignore').strip('\x00 ')
                else:
                    val = chunk.hex().upper()

                self.attributes[attr_name] = val

                offset += length

# vim: set ts=4 sw=4 et:

#TRUSTED 233b8091d22466edb1a756f92c754ac960f352d94ccfe396b8833783d31d5677aa8c9d9662d92a17942d1cb7a1f71cf66131e4d7b22aaf81d364befd738020816dc3fa44afdf52ec2b34e05c4a9f84ca0f9767b032b65dc5c6bfcfbd1e3d1ef0707e9effad49c73a890d14c71c271111e6ab4e075de175b49e396241405f871be56d0d03b83d0d1cc6b6f48d9c778d2acd3f274281ab5310f6a87c975d3cd7cf8244b8ee63e15c0a01d993a1ea44f060c0104d99b210abaf7943e9722c9f12424a334ad803bca2bba38926732bbd62827a8ca54d68eaa5dbbcbde613d0e7c5a06a1966781b0861d87406d2a05894edd5f32eac52e9fbd92672ae9de6feb60f0f6d1e58c276710136ce15b22cfad3a9ad52cab599166b15735019ffa5bc8acd64ada79b58508c2408e8dade85b768fc8ac8474af0ed274e837700522e2a96a9f160fd8acce7a358cf10bc9dd1b3b4a2be53ad321825beaf3c5cc88d98302622a53b19f987378fc66f74c6f31fc00d7dd112ea0757b95581425b0337f6f107bb9d9c4af98d02370140cda6cf314d901b6b340e7a956354c4120d18a6f87e3f4c1d0315fa25f06e96ccb6ed2c8d109d8cc0cfeb234912a603b4c99f30e3fdb1fb3ea13e7cbb3ea5130f825da35374c2623696b81b9e6c4953f787ad09d6d71b7ad3bb0aa75bdfc8097342568cf5258164b8698240b6a0d61b1c7471da4a23e92a05
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a964bc.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49034);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2009-0629");
 script_bugtraq_id(34238);
 script_osvdb_id(53136);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsr29468");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090325-tcp");
 script_name(english:"Cisco IOS Software Multiple Features Crafted TCP Sequence Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco IOS Software contains a vulnerability in multiple features that
could allow an attacker to cause a denial of service (DoS) condition on
the affected device. A sequence of specially crafted TCP packets can
cause the vulnerable device to reload.
Cisco has released free software updates that address this
vulnerability.
Several mitigation strategies are outlined in the workarounds section
of this advisory.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3c7d471");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a964bc.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?3a842ed7");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090325-tcp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/03/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(15)XY3') flag++;
else if (version == '12.4(15)XY2') flag++;
else if (version == '12.4(15)XY1') flag++;
else if (version == '12.4(15)XY') flag++;
else if (version == '12.4(15)XR3') flag++;
else if (version == '12.4(15)XR2') flag++;
else if (version == '12.4(15)XR1') flag++;
else if (version == '12.4(15)XR') flag++;
else if (version == '12.4(15)XQ1') flag++;
else if (version == '12.4(15)XQ') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(19)MR') flag++;
else if (version == '12.4(15)MD1') flag++;
else if (version == '12.4(15)MD') flag++;
else if (version == '12.2(18)ZYA') flag++;
else if (version == '12.2(18)ZY2') flag++;
else if (version == '12.2(18)ZY1') flag++;
else if (version == '12.2(18)ZY') flag++;
else if (version == '12.2(28)ZX') flag++;
else if (version == '12.2(18)ZU2') flag++;
else if (version == '12.2(18)ZU1') flag++;
else if (version == '12.2(18)ZU') flag++;
else if (version == '12.2(40)XO') flag++;
else if (version == '12.2(33)XN1') flag++;
else if (version == '12.2(14)SZ6') flag++;
else if (version == '12.2(14)SZ5') flag++;
else if (version == '12.2(14)SZ4') flag++;
else if (version == '12.2(14)SZ3') flag++;
else if (version == '12.2(14)SZ2') flag++;
else if (version == '12.2(14)SZ1') flag++;
else if (version == '12.2(14)SZ') flag++;
else if (version == '12.2(33)SXI') flag++;
else if (version == '12.2(33)SXH4') flag++;
else if (version == '12.2(33)SXH3a') flag++;
else if (version == '12.2(33)SXH3') flag++;
else if (version == '12.2(33)SXH2a') flag++;
else if (version == '12.2(33)SXH2') flag++;
else if (version == '12.2(33)SXH1') flag++;
else if (version == '12.2(33)SXH') flag++;
else if (version == '12.2(18)SXF9') flag++;
else if (version == '12.2(18)SXF8') flag++;
else if (version == '12.2(18)SXF7') flag++;
else if (version == '12.2(18)SXF6') flag++;
else if (version == '12.2(18)SXF5') flag++;
else if (version == '12.2(18)SXF4') flag++;
else if (version == '12.2(18)SXF3') flag++;
else if (version == '12.2(18)SXF2') flag++;
else if (version == '12.2(18)SXF15a') flag++;
else if (version == '12.2(18)SXF15') flag++;
else if (version == '12.2(18)SXF14') flag++;
else if (version == '12.2(18)SXF13') flag++;
else if (version == '12.2(18)SXF12a') flag++;
else if (version == '12.2(18)SXF12') flag++;
else if (version == '12.2(18)SXF11') flag++;
else if (version == '12.2(18)SXF10a') flag++;
else if (version == '12.2(18)SXF10') flag++;
else if (version == '12.2(18)SXF1') flag++;
else if (version == '12.2(18)SXF') flag++;
else if (version == '12.2(18)SXE6b') flag++;
else if (version == '12.2(18)SXE6a') flag++;
else if (version == '12.2(18)SXE6') flag++;
else if (version == '12.2(18)SXE5') flag++;
else if (version == '12.2(18)SXE4') flag++;
else if (version == '12.2(18)SXE3') flag++;
else if (version == '12.2(18)SXE2') flag++;
else if (version == '12.2(18)SXE1') flag++;
else if (version == '12.2(18)SXE') flag++;
else if (version == '12.2(18)SXD7b') flag++;
else if (version == '12.2(18)SXD7a') flag++;
else if (version == '12.2(18)SXD7') flag++;
else if (version == '12.2(18)SXD6') flag++;
else if (version == '12.2(18)SXD5') flag++;
else if (version == '12.2(18)SXD4') flag++;
else if (version == '12.2(18)SXD3') flag++;
else if (version == '12.2(18)SXD2') flag++;
else if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(18)SXD') flag++;
else if (version == '12.2(25)SW9') flag++;
else if (version == '12.2(25)SW8') flag++;
else if (version == '12.2(25)SW7') flag++;
else if (version == '12.2(25)SW6') flag++;
else if (version == '12.2(25)SW5') flag++;
else if (version == '12.2(25)SW4a') flag++;
else if (version == '12.2(25)SW4') flag++;
else if (version == '12.2(25)SW3a') flag++;
else if (version == '12.2(25)SW3') flag++;
else if (version == '12.2(25)SW2') flag++;
else if (version == '12.2(25)SW12') flag++;
else if (version == '12.2(25)SW11') flag++;
else if (version == '12.2(25)SW10') flag++;
else if (version == '12.2(25)SW1') flag++;
else if (version == '12.2(23)SW1') flag++;
else if (version == '12.2(23)SW') flag++;
else if (version == '12.2(21)SW1') flag++;
else if (version == '12.2(21)SW') flag++;
else if (version == '12.2(20)SW') flag++;
else if (version == '12.2(19)SW') flag++;
else if (version == '12.2(18)SW') flag++;
else if (version == '12.2(29)SVE0') flag++;
else if (version == '12.2(29)SVD1') flag++;
else if (version == '12.2(29)SVD0') flag++;
else if (version == '12.2(29)SVD') flag++;
else if (version == '12.2(29)SVC') flag++;
else if (version == '12.2(29)SVA2') flag++;
else if (version == '12.2(29b)SV1') flag++;
else if (version == '12.2(29b)SV') flag++;
else if (version == '12.2(29a)SV1') flag++;
else if (version == '12.2(29a)SV') flag++;
else if (version == '12.2(29)SV3') flag++;
else if (version == '12.2(29)SV2') flag++;
else if (version == '12.2(29)SV1') flag++;
else if (version == '12.2(29)SV') flag++;
else if (version == '12.2(28)SV2') flag++;
else if (version == '12.2(28)SV1') flag++;
else if (version == '12.2(28)SV') flag++;
else if (version == '12.2(27)SV5') flag++;
else if (version == '12.2(27)SV4') flag++;
else if (version == '12.2(27)SV3') flag++;
else if (version == '12.2(27)SV2') flag++;
else if (version == '12.2(27)SV1') flag++;
else if (version == '12.2(27)SV') flag++;
else if (version == '12.2(26)SV1') flag++;
else if (version == '12.2(26)SV') flag++;
else if (version == '12.2(25)SV3') flag++;
else if (version == '12.2(25)SV2') flag++;
else if (version == '12.2(25)SV') flag++;
else if (version == '12.2(24)SV1') flag++;
else if (version == '12.2(24)SV') flag++;
else if (version == '12.2(23)SV1') flag++;
else if (version == '12.2(23)SV') flag++;
else if (version == '12.2(22)SV1') flag++;
else if (version == '12.2(22)SV') flag++;
else if (version == '12.2(18)SV3') flag++;
else if (version == '12.2(18)SV2') flag++;
else if (version == '12.2(18)SV1') flag++;
else if (version == '12.2(18)SV') flag++;
else if (version == '12.2(33)STE0') flag++;
else if (version == '12.2(33)SRD') flag++;
else if (version == '12.2(33)SRC2') flag++;
else if (version == '12.2(33)SRC1') flag++;
else if (version == '12.2(33)SRC') flag++;
else if (version == '12.2(33)SRB5') flag++;
else if (version == '12.2(33)SRB4') flag++;
else if (version == '12.2(33)SRB3') flag++;
else if (version == '12.2(33)SRB2') flag++;
else if (version == '12.2(33)SRB1') flag++;
else if (version == '12.2(33)SRB') flag++;
else if (version == '12.2(33)SRA7') flag++;
else if (version == '12.2(33)SRA6') flag++;
else if (version == '12.2(33)SRA5') flag++;
else if (version == '12.2(33)SRA4') flag++;
else if (version == '12.2(33)SRA3') flag++;
else if (version == '12.2(33)SRA2') flag++;
else if (version == '12.2(33)SRA1') flag++;
else if (version == '12.2(33)SRA') flag++;
else if (version == '12.2(18)SO7') flag++;
else if (version == '12.2(18)SO6') flag++;
else if (version == '12.2(18)SO5') flag++;
else if (version == '12.2(18)SO4') flag++;
else if (version == '12.2(18)SO3') flag++;
else if (version == '12.2(18)SO2') flag++;
else if (version == '12.2(18)SO1') flag++;
else if (version == '12.2(29)SM4') flag++;
else if (version == '12.2(29)SM3') flag++;
else if (version == '12.2(29)SM2') flag++;
else if (version == '12.2(29)SM1') flag++;
else if (version == '12.2(29)SM') flag++;
else if (version == '12.2(31)SGA8') flag++;
else if (version == '12.2(31)SGA7') flag++;
else if (version == '12.2(31)SGA6') flag++;
else if (version == '12.2(31)SGA5') flag++;
else if (version == '12.2(31)SGA4') flag++;
else if (version == '12.2(31)SGA3') flag++;
else if (version == '12.2(31)SGA2') flag++;
else if (version == '12.2(31)SGA1') flag++;
else if (version == '12.2(31)SGA') flag++;
else if (version == '12.2(46)SG1') flag++;
else if (version == '12.2(46)SG') flag++;
else if (version == '12.2(44)SG1') flag++;
else if (version == '12.2(44)SG') flag++;
else if (version == '12.2(40)SG') flag++;
else if (version == '12.2(37)SG1') flag++;
else if (version == '12.2(37)SG') flag++;
else if (version == '12.2(31)SG3') flag++;
else if (version == '12.2(31)SG2') flag++;
else if (version == '12.2(31)SG1') flag++;
else if (version == '12.2(31)SG') flag++;
else if (version == '12.2(25)SG4') flag++;
else if (version == '12.2(25)SG3') flag++;
else if (version == '12.2(25)SG2') flag++;
else if (version == '12.2(25)SG1') flag++;
else if (version == '12.2(25)SG') flag++;
else if (version == '12.2(25)SEG3') flag++;
else if (version == '12.2(25)SEG1') flag++;
else if (version == '12.2(25)SEG') flag++;
else if (version == '12.2(25)SEE4') flag++;
else if (version == '12.2(25)SEE3') flag++;
else if (version == '12.2(25)SEE2') flag++;
else if (version == '12.2(25)SEE1') flag++;
else if (version == '12.2(25)SEE') flag++;
else if (version == '12.2(25)SED1') flag++;
else if (version == '12.2(25)SED') flag++;
else if (version == '12.2(25)SEC2') flag++;
else if (version == '12.2(25)SEC1') flag++;
else if (version == '12.2(25)SEC') flag++;
else if (version == '12.2(25)SEB4') flag++;
else if (version == '12.2(25)SEB3') flag++;
else if (version == '12.2(25)SEB2') flag++;
else if (version == '12.2(25)SEB1') flag++;
else if (version == '12.2(25)SEB') flag++;
else if (version == '12.2(25)SEA') flag++;
else if (version == '12.2(46)SE') flag++;
else if (version == '12.2(44)SE4') flag++;
else if (version == '12.2(44)SE3') flag++;
else if (version == '12.2(44)SE2') flag++;
else if (version == '12.2(44)SE1') flag++;
else if (version == '12.2(44)SE') flag++;
else if (version == '12.2(40)SE1') flag++;
else if (version == '12.2(40)SE') flag++;
else if (version == '12.2(37)SE1') flag++;
else if (version == '12.2(37)SE') flag++;
else if (version == '12.2(35)SE5') flag++;
else if (version == '12.2(35)SE4') flag++;
else if (version == '12.2(35)SE3') flag++;
else if (version == '12.2(35)SE2') flag++;
else if (version == '12.2(35)SE1') flag++;
else if (version == '12.2(35)SE') flag++;
else if (version == '12.2(25)SE') flag++;
else if (version == '12.2(20)SE4') flag++;
else if (version == '12.2(20)SE3') flag++;
else if (version == '12.2(20)SE1') flag++;
else if (version == '12.2(20)SE') flag++;
else if (version == '12.2(18)SE1') flag++;
else if (version == '12.2(18)SE') flag++;
else if (version == '12.2(33)SCB') flag++;
else if (version == '12.2(33)SCA2') flag++;
else if (version == '12.2(33)SCA1') flag++;
else if (version == '12.2(33)SCA') flag++;
else if (version == '12.2(27)SBC5') flag++;
else if (version == '12.2(27)SBC4') flag++;
else if (version == '12.2(27)SBC3') flag++;
else if (version == '12.2(27)SBC2') flag++;
else if (version == '12.2(27)SBC1') flag++;
else if (version == '12.2(27)SBC') flag++;
else if (version == '12.2(27)SBB4e') flag++;
else if (version == '12.2(33)SB2') flag++;
else if (version == '12.2(33)SB1') flag++;
else if (version == '12.2(33)SB') flag++;
else if (version == '12.2(31)SB9') flag++;
else if (version == '12.2(31)SB8') flag++;
else if (version == '12.2(31)SB7') flag++;
else if (version == '12.2(31)SB6') flag++;
else if (version == '12.2(31)SB5') flag++;
else if (version == '12.2(31)SB3x') flag++;
else if (version == '12.2(31)SB3') flag++;
else if (version == '12.2(31)SB2') flag++;
else if (version == '12.2(31)SB13') flag++;
else if (version == '12.2(31)SB12') flag++;
else if (version == '12.2(31)SB11') flag++;
else if (version == '12.2(31)SB10') flag++;
else if (version == '12.2(28)SB9') flag++;
else if (version == '12.2(28)SB8') flag++;
else if (version == '12.2(28)SB7') flag++;
else if (version == '12.2(28)SB6') flag++;
else if (version == '12.2(28)SB5c') flag++;
else if (version == '12.2(28)SB5') flag++;
else if (version == '12.2(28)SB4d') flag++;
else if (version == '12.2(28)SB4') flag++;
else if (version == '12.2(28)SB3') flag++;
else if (version == '12.2(28)SB2') flag++;
else if (version == '12.2(28)SB12') flag++;
else if (version == '12.2(28)SB11') flag++;
else if (version == '12.2(28)SB10') flag++;
else if (version == '12.2(28)SB1') flag++;
else if (version == '12.2(28)SB') flag++;
else if (version == '12.2(30)S1') flag++;
else if (version == '12.2(30)S') flag++;
else if (version == '12.2(25)S9') flag++;
else if (version == '12.2(25)S8') flag++;
else if (version == '12.2(25)S7') flag++;
else if (version == '12.2(25)S6') flag++;
else if (version == '12.2(25)S5') flag++;
else if (version == '12.2(25)S4') flag++;
else if (version == '12.2(25)S3') flag++;
else if (version == '12.2(25)S2') flag++;
else if (version == '12.2(25)S15') flag++;
else if (version == '12.2(25)S14') flag++;
else if (version == '12.2(25)S13') flag++;
else if (version == '12.2(25)S12') flag++;
else if (version == '12.2(25)S11') flag++;
else if (version == '12.2(25)S10') flag++;
else if (version == '12.2(25)S1') flag++;
else if (version == '12.2(25)S') flag++;
else if (version == '12.2(22)S2') flag++;
else if (version == '12.2(22)S1') flag++;
else if (version == '12.2(22)S') flag++;
else if (version == '12.2(20)S9') flag++;
else if (version == '12.2(20)S8') flag++;
else if (version == '12.2(20)S7') flag++;
else if (version == '12.2(20)S6') flag++;
else if (version == '12.2(20)S5') flag++;
else if (version == '12.2(20)S4') flag++;
else if (version == '12.2(20)S3') flag++;
else if (version == '12.2(20)S2') flag++;
else if (version == '12.2(20)S14') flag++;
else if (version == '12.2(20)S13') flag++;
else if (version == '12.2(20)S12') flag++;
else if (version == '12.2(20)S11') flag++;
else if (version == '12.2(20)S10') flag++;
else if (version == '12.2(20)S1') flag++;
else if (version == '12.2(20)S') flag++;
else if (version == '12.2(18)S9') flag++;
else if (version == '12.2(18)S8') flag++;
else if (version == '12.2(18)S7') flag++;
else if (version == '12.2(18)S6') flag++;
else if (version == '12.2(18)S5') flag++;
else if (version == '12.2(18)S4') flag++;
else if (version == '12.2(18)S3') flag++;
else if (version == '12.2(18)S2') flag++;
else if (version == '12.2(18)S13') flag++;
else if (version == '12.2(18)S12') flag++;
else if (version == '12.2(18)S11') flag++;
else if (version == '12.2(18)S10') flag++;
else if (version == '12.2(18)S1') flag++;
else if (version == '12.2(18)S') flag++;
else if (version == '12.2(18)IXG') flag++;
else if (version == '12.2(18)IXF1') flag++;
else if (version == '12.2(18)IXF') flag++;
else if (version == '12.2(18)IXE') flag++;
else if (version == '12.2(18)IXD1') flag++;
else if (version == '12.2(18)IXD') flag++;
else if (version == '12.2(18)IXC') flag++;
else if (version == '12.2(18)IXB2') flag++;
else if (version == '12.2(18)IXB1') flag++;
else if (version == '12.2(18)IXB') flag++;
else if (version == '12.2(18)IXA') flag++;
else if (version == '12.2(33)IRB') flag++;
else if (version == '12.2(33)IRA') flag++;
else if (version == '12.2(25)FZ') flag++;
else if (version == '12.2(25)EZ1') flag++;
else if (version == '12.2(25)EZ') flag++;
else if (version == '12.2(25)EY4') flag++;
else if (version == '12.2(25)EY3') flag++;
else if (version == '12.2(25)EY2') flag++;
else if (version == '12.2(25)EY1') flag++;
else if (version == '12.2(25)EY') flag++;
else if (version == '12.2(40)EX3') flag++;
else if (version == '12.2(40)EX2') flag++;
else if (version == '12.2(40)EX1') flag++;
else if (version == '12.2(40)EX') flag++;
else if (version == '12.2(25)EX1') flag++;
else if (version == '12.2(25)EX') flag++;
else if (version == '12.2(20)EX') flag++;
else if (version == '12.2(25)EWA9') flag++;
else if (version == '12.2(25)EWA8') flag++;
else if (version == '12.2(25)EWA7') flag++;
else if (version == '12.2(25)EWA6') flag++;
else if (version == '12.2(25)EWA5') flag++;
else if (version == '12.2(25)EWA4') flag++;
else if (version == '12.2(25)EWA3') flag++;
else if (version == '12.2(25)EWA2') flag++;
else if (version == '12.2(25)EWA14') flag++;
else if (version == '12.2(25)EWA13') flag++;
else if (version == '12.2(25)EWA12') flag++;
else if (version == '12.2(25)EWA11') flag++;
else if (version == '12.2(25)EWA10') flag++;
else if (version == '12.2(25)EWA1') flag++;
else if (version == '12.2(25)EWA') flag++;
else if (version == '12.2(20)EWA4') flag++;
else if (version == '12.2(20)EWA3') flag++;
else if (version == '12.2(20)EWA2') flag++;
else if (version == '12.2(20)EWA1') flag++;
else if (version == '12.2(20)EWA') flag++;
else if (version == '12.2(25)EW') flag++;
else if (version == '12.2(20)EW4') flag++;
else if (version == '12.2(20)EW3') flag++;
else if (version == '12.2(20)EW2') flag++;
else if (version == '12.2(20)EW1') flag++;
else if (version == '12.2(20)EW') flag++;
else if (version == '12.2(18)EW7') flag++;
else if (version == '12.2(18)EW6') flag++;
else if (version == '12.2(18)EW5') flag++;
else if (version == '12.2(18)EW4') flag++;
else if (version == '12.2(18)EW3') flag++;
else if (version == '12.2(18)EW2') flag++;
else if (version == '12.2(18)EW1') flag++;
else if (version == '12.2(18)EW') flag++;
else if (version == '12.2(20)EU2') flag++;
else if (version == '12.2(20)EU1') flag++;
else if (version == '12.2(20)EU') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"vpdn enable", multiline:TRUE, string:buf)) && (preg(pattern:"protocol pptp", multiline:TRUE, string:buf)) ) { flag = 1; }
      if ( (preg(pattern:"vpdn enable", multiline:TRUE, string:buf)) && (preg(pattern:"protocol any", multiline:TRUE, string:buf)) ) { flag = 1; }
      if (preg(pattern:"alps local-peer ", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"encapsulation stun", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"encapsulation bstun", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ncia server ", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"dlsw local-peer peer-id ", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"source-bridge [^\r\n]+ tcp", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"x25 map [^\r\n]+rbp", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"xot access-group ", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"x25 routing", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

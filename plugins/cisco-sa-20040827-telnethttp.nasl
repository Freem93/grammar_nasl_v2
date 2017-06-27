#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00802acbf6.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48977);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2004-1464");
 script_bugtraq_id(11060);
 script_osvdb_id(9265);
 script_xref(name:"CERT", value:"384230");
 script_name(english:"Cisco Telnet Denial of Service Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'A specially crafted Transmission Control Protocol (TCP) connection
to a telnet or reverse telnet port of a Cisco device running
Internetwork Operating System (IOS) may block further telnet, reverse
telnet, Remote Shell (RSH), Secure Shell (SSH), and in some cases
Hypertext Transport Protocol (HTTP) access to the Cisco device. Data
Link Switching (DLSw) and protocol translation connections may also be
affected.');
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?5bb6a85b");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00802acbf6.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?6f3d9fe1");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040827-telnet."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/27");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/08/27");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCef46191");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20040827-telnet");
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}
include("cisco_func.inc");

#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.3(8)YA')
  security_warning(0);
else if (version == '12.3(2)XZ2')
  security_warning(0);
else if (version == '12.3(2)XZ1')
  security_warning(0);
else if (version == '12.3(2)XZ')
  security_warning(0);
else if (version == '12.3(8)XY6')
  security_warning(0);
else if (version == '12.3(8)XY5')
  security_warning(0);
else if (version == '12.3(8)XY4')
  security_warning(0);
else if (version == '12.3(8)XY3')
  security_warning(0);
else if (version == '12.3(8)XY2')
  security_warning(0);
else if (version == '12.3(8)XY1')
  security_warning(0);
else if (version == '12.3(8)XY')
  security_warning(0);
else if (version == '12.3(8)XX')
  security_warning(0);
else if (version == '12.3(8)XW3')
  security_warning(0);
else if (version == '12.3(8)XW2')
  security_warning(0);
else if (version == '12.3(8)XW1')
  security_warning(0);
else if (version == '12.3(8)XW')
  security_warning(0);
else if (version == '12.3(8)XU1')
  security_warning(0);
else if (version == '12.3(8)XU')
  security_warning(0);
else if (version == '12.3(7)XS1')
  security_warning(0);
else if (version == '12.3(7)XS')
  security_warning(0);
else if (version == '12.3(7)XR2')
  security_warning(0);
else if (version == '12.3(7)XR')
  security_warning(0);
else if (version == '12.3(4)XQ')
  security_warning(0);
else if (version == '12.3(4)XK')
  security_warning(0);
else if (version == '12.3(7)XJ2')
  security_warning(0);
else if (version == '12.3(7)XJ1')
  security_warning(0);
else if (version == '12.3(7)XJ')
  security_warning(0);
else if (version == '12.3(7)XI1c')
  security_warning(0);
else if (version == '12.3(7)XI1b')
  security_warning(0);
else if (version == '12.3(7)XI1')
  security_warning(0);
else if (version == '12.3(4)XG1')
  security_warning(0);
else if (version == '12.3(4)XG')
  security_warning(0);
else if (version == '12.3(2)XF')
  security_warning(0);
else if (version == '12.3(2)XE')
  security_warning(0);
else if (version == '12.3(4)XD3')
  security_warning(0);
else if (version == '12.3(4)XD2')
  security_warning(0);
else if (version == '12.3(4)XD1')
  security_warning(0);
else if (version == '12.3(4)XD')
  security_warning(0);
else if (version == '12.3(2)XC2')
  security_warning(0);
else if (version == '12.3(2)XC1')
  security_warning(0);
else if (version == '12.3(2)XC')
  security_warning(0);
else if (version == '12.3(2)XB3')
  security_warning(0);
else if (version == '12.3(2)XB1')
  security_warning(0);
else if (version == '12.3(2)XB')
  security_warning(0);
else if (version == '12.3(2)XA4')
  security_warning(0);
else if (version == '12.3(2)XA3')
  security_warning(0);
else if (version == '12.3(2)XA2')
  security_warning(0);
else if (version == '12.3(2)XA1')
  security_warning(0);
else if (version == '12.3(2)XA')
  security_warning(0);
else if (version == '12.3(8)T3')
  security_warning(0);
else if (version == '12.3(8)T1')
  security_warning(0);
else if (version == '12.3(8)T')
  security_warning(0);
else if (version == '12.3(7)T3')
  security_warning(0);
else if (version == '12.3(7)T2')
  security_warning(0);
else if (version == '12.3(7)T1')
  security_warning(0);
else if (version == '12.3(7)T')
  security_warning(0);
else if (version == '12.3(4)T7')
  security_warning(0);
else if (version == '12.3(4)T6')
  security_warning(0);
else if (version == '12.3(4)T4')
  security_warning(0);
else if (version == '12.3(4)T3')
  security_warning(0);
else if (version == '12.3(4)T2a')
  security_warning(0);
else if (version == '12.3(4)T2')
  security_warning(0);
else if (version == '12.3(4)T1')
  security_warning(0);
else if (version == '12.3(4)T')
  security_warning(0);
else if (version == '12.3(2)T7')
  security_warning(0);
else if (version == '12.3(2)T6')
  security_warning(0);
else if (version == '12.3(2)T5')
  security_warning(0);
else if (version == '12.3(2)T4')
  security_warning(0);
else if (version == '12.3(2)T3')
  security_warning(0);
else if (version == '12.3(2)T2')
  security_warning(0);
else if (version == '12.3(2)T1')
  security_warning(0);
else if (version == '12.3(2)T')
  security_warning(0);
else if (version == '12.3(4)JA2')
  security_warning(0);
else if (version == '12.3(4)JA1')
  security_warning(0);
else if (version == '12.3(4)JA')
  security_warning(0);
else if (version == '12.3(1a)BW')
  security_warning(0);
else if (version == '12.3(5a)B1')
  security_warning(0);
else if (version == '12.3(5a)B')
  security_warning(0);
else if (version == '12.3(3)B1')
  security_warning(0);
else if (version == '12.3(3)B')
  security_warning(0);
else if (version == '12.3(1a)B')
  security_warning(0);
else if (version == '12.3(10)')
  security_warning(0);
else if (version == '12.3(9b)')
  security_warning(0);
else if (version == '12.3(9a)')
  security_warning(0);
else if (version == '12.3(9)')
  security_warning(0);
else if (version == '12.3(6c)')
  security_warning(0);
else if (version == '12.3(6b)')
  security_warning(0);
else if (version == '12.3(6a)')
  security_warning(0);
else if (version == '12.3(6)')
  security_warning(0);
else if (version == '12.3(5d)')
  security_warning(0);
else if (version == '12.3(5c)')
  security_warning(0);
else if (version == '12.3(5b)')
  security_warning(0);
else if (version == '12.3(5a)')
  security_warning(0);
else if (version == '12.3(5)')
  security_warning(0);
else if (version == '12.3(3g)')
  security_warning(0);
else if (version == '12.3(3f)')
  security_warning(0);
else if (version == '12.3(3e)')
  security_warning(0);
else if (version == '12.3(3c)')
  security_warning(0);
else if (version == '12.3(3b)')
  security_warning(0);
else if (version == '12.3(3a)')
  security_warning(0);
else if (version == '12.3(3)')
  security_warning(0);
else if (version == '12.3(1a)')
  security_warning(0);
else if (version == '12.3(1)')
  security_warning(0);
else if (version == '12.2(13)ZP4')
  security_warning(0);
else if (version == '12.2(13)ZP3')
  security_warning(0);
else if (version == '12.2(13)ZP2')
  security_warning(0);
else if (version == '12.2(13)ZP1')
  security_warning(0);
else if (version == '12.2(13)ZP')
  security_warning(0);
else if (version == '12.2(15)ZL1')
  security_warning(0);
else if (version == '12.2(15)ZL')
  security_warning(0);
else if (version == '12.2(15)ZJ5')
  security_warning(0);
else if (version == '12.2(15)ZJ3')
  security_warning(0);
else if (version == '12.2(15)ZJ2')
  security_warning(0);
else if (version == '12.2(15)ZJ1')
  security_warning(0);
else if (version == '12.2(15)ZJ')
  security_warning(0);
else if (version == '12.2(13)ZH7')
  security_warning(0);
else if (version == '12.2(13)ZH6')
  security_warning(0);
else if (version == '12.2(13)ZH5')
  security_warning(0);
else if (version == '12.2(13)ZH4')
  security_warning(0);
else if (version == '12.2(13)ZH3')
  security_warning(0);
else if (version == '12.2(13)ZH2')
  security_warning(0);
else if (version == '12.2(13)ZH1')
  security_warning(0);
else if (version == '12.2(13)ZH')
  security_warning(0);
else if (version == '12.2(13)ZG')
  security_warning(0);
else if (version == '12.2(13)ZF2')
  security_warning(0);
else if (version == '12.2(13)ZF1')
  security_warning(0);
else if (version == '12.2(13)ZF')
  security_warning(0);
else if (version == '12.2(13)ZE')
  security_warning(0);
else if (version == '12.2(13)ZD4')
  security_warning(0);
else if (version == '12.2(13)ZD3')
  security_warning(0);
else if (version == '12.2(13)ZD2')
  security_warning(0);
else if (version == '12.2(13)ZD1')
  security_warning(0);
else if (version == '12.2(13)ZD')
  security_warning(0);
else if (version == '12.2(13)ZC')
  security_warning(0);
else if (version == '12.2(11)ZC')
  security_warning(0);
else if (version == '12.2(8)ZB8')
  security_warning(0);
else if (version == '12.2(8)ZB7')
  security_warning(0);
else if (version == '12.2(8)ZB6')
  security_warning(0);
else if (version == '12.2(8)ZB5')
  security_warning(0);
else if (version == '12.2(8)ZB4a')
  security_warning(0);
else if (version == '12.2(8)ZB4')
  security_warning(0);
else if (version == '12.2(8)ZB3')
  security_warning(0);
else if (version == '12.2(8)ZB2')
  security_warning(0);
else if (version == '12.2(8)ZB1')
  security_warning(0);
else if (version == '12.2(8)ZB')
  security_warning(0);
else if (version == '12.2(14)ZA7')
  security_warning(0);
else if (version == '12.2(14)ZA6')
  security_warning(0);
else if (version == '12.2(14)ZA5')
  security_warning(0);
else if (version == '12.2(14)ZA4')
  security_warning(0);
else if (version == '12.2(14)ZA3')
  security_warning(0);
else if (version == '12.2(14)ZA2')
  security_warning(0);
else if (version == '12.2(14)ZA1')
  security_warning(0);
else if (version == '12.2(14)ZA')
  security_warning(0);
else if (version == '12.2(9)ZA')
  security_warning(0);
else if (version == '12.2(11)YZ2')
  security_warning(0);
else if (version == '12.2(11)YZ1')
  security_warning(0);
else if (version == '12.2(11)YZ')
  security_warning(0);
else if (version == '12.2(8)YY4')
  security_warning(0);
else if (version == '12.2(8)YY3')
  security_warning(0);
else if (version == '12.2(8)YY2')
  security_warning(0);
else if (version == '12.2(8)YY1')
  security_warning(0);
else if (version == '12.2(8)YY')
  security_warning(0);
else if (version == '12.2(11)YX1')
  security_warning(0);
else if (version == '12.2(11)YX')
  security_warning(0);
else if (version == '12.2(8)YW3')
  security_warning(0);
else if (version == '12.2(8)YW2')
  security_warning(0);
else if (version == '12.2(8)YW1')
  security_warning(0);
else if (version == '12.2(8)YW')
  security_warning(0);
else if (version == '12.2(11)YV1')
  security_warning(0);
else if (version == '12.2(11)YV')
  security_warning(0);
else if (version == '12.2(11)YU')
  security_warning(0);
else if (version == '12.2(11)YT2')
  security_warning(0);
else if (version == '12.2(11)YT1')
  security_warning(0);
else if (version == '12.2(11)YT')
  security_warning(0);
else if (version == '12.2(11)YR')
  security_warning(0);
else if (version == '12.2(11)YQ')
  security_warning(0);
else if (version == '12.2(11)YP3')
  security_warning(0);
else if (version == '12.2(8)YN1')
  security_warning(0);
else if (version == '12.2(8)YN')
  security_warning(0);
else if (version == '12.2(8)YM')
  security_warning(0);
else if (version == '12.2(8)YL')
  security_warning(0);
else if (version == '12.2(2)YK1')
  security_warning(0);
else if (version == '12.2(2)YK')
  security_warning(0);
else if (version == '12.2(8)YJ1')
  security_warning(0);
else if (version == '12.2(8)YJ')
  security_warning(0);
else if (version == '12.2(4)YH')
  security_warning(0);
else if (version == '12.2(4)YG')
  security_warning(0);
else if (version == '12.2(4)YF')
  security_warning(0);
else if (version == '12.2(9)YE')
  security_warning(0);
else if (version == '12.2(8)YD3')
  security_warning(0);
else if (version == '12.2(8)YD2')
  security_warning(0);
else if (version == '12.2(8)YD1')
  security_warning(0);
else if (version == '12.2(8)YD')
  security_warning(0);
else if (version == '12.2(2)YC4')
  security_warning(0);
else if (version == '12.2(2)YC3')
  security_warning(0);
else if (version == '12.2(2)YC2')
  security_warning(0);
else if (version == '12.2(2)YC1')
  security_warning(0);
else if (version == '12.2(2)YC')
  security_warning(0);
else if (version == '12.2(4)YB')
  security_warning(0);
else if (version == '12.2(4)YA7')
  security_warning(0);
else if (version == '12.2(4)YA6')
  security_warning(0);
else if (version == '12.2(4)YA5')
  security_warning(0);
else if (version == '12.2(4)YA4')
  security_warning(0);
else if (version == '12.2(4)YA3')
  security_warning(0);
else if (version == '12.2(4)YA2')
  security_warning(0);
else if (version == '12.2(4)YA1')
  security_warning(0);
else if (version == '12.2(4)YA')
  security_warning(0);
else if (version == '12.2(4)XW')
  security_warning(0);
else if (version == '12.2(4)XV5')
  security_warning(0);
else if (version == '12.2(4)XV4a')
  security_warning(0);
else if (version == '12.2(4)XV4')
  security_warning(0);
else if (version == '12.2(4)XV3')
  security_warning(0);
else if (version == '12.2(4)XV2')
  security_warning(0);
else if (version == '12.2(4)XV1')
  security_warning(0);
else if (version == '12.2(4)XV')
  security_warning(0);
else if (version == '12.2(2)XU1')
  security_warning(0);
else if (version == '12.2(2)XU')
  security_warning(0);
else if (version == '12.2(2)XT3')
  security_warning(0);
else if (version == '12.2(2)XT2')
  security_warning(0);
else if (version == '12.2(2)XT1')
  security_warning(0);
else if (version == '12.2(2)XT')
  security_warning(0);
else if (version == '12.2(1)XS2')
  security_warning(0);
else if (version == '12.2(1)XS1a')
  security_warning(0);
else if (version == '12.2(1)XS1')
  security_warning(0);
else if (version == '12.2(1)XS')
  security_warning(0);
else if (version == '12.2(15)XR1')
  security_warning(0);
else if (version == '12.2(15)XR')
  security_warning(0);
else if (version == '12.2(4)XR')
  security_warning(0);
else if (version == '12.2(2)XR')
  security_warning(0);
else if (version == '12.2(2)XQ1')
  security_warning(0);
else if (version == '12.2(2)XQ')
  security_warning(0);
else if (version == '12.2(2)XN')
  security_warning(0);
else if (version == '12.2(4)XM4')
  security_warning(0);
else if (version == '12.2(4)XM3')
  security_warning(0);
else if (version == '12.2(4)XM2')
  security_warning(0);
else if (version == '12.2(4)XM1')
  security_warning(0);
else if (version == '12.2(4)XM')
  security_warning(0);
else if (version == '12.2(4)XL6')
  security_warning(0);
else if (version == '12.2(4)XL5')
  security_warning(0);
else if (version == '12.2(4)XL4')
  security_warning(0);
else if (version == '12.2(4)XL3')
  security_warning(0);
else if (version == '12.2(4)XL2')
  security_warning(0);
else if (version == '12.2(4)XL1')
  security_warning(0);
else if (version == '12.2(4)XL')
  security_warning(0);
else if (version == '12.2(2)XK3')
  security_warning(0);
else if (version == '12.2(2)XK2')
  security_warning(0);
else if (version == '12.2(2)XK1')
  security_warning(0);
else if (version == '12.2(2)XK')
  security_warning(0);
else if (version == '12.2(2)XJ')
  security_warning(0);
else if (version == '12.2(2)XI2')
  security_warning(0);
else if (version == '12.2(2)XI1')
  security_warning(0);
else if (version == '12.2(2)XI')
  security_warning(0);
else if (version == '12.2(2)XH2')
  security_warning(0);
else if (version == '12.2(2)XH1')
  security_warning(0);
else if (version == '12.2(2)XH')
  security_warning(0);
else if (version == '12.2(2)XG1')
  security_warning(0);
else if (version == '12.2(2)XG')
  security_warning(0);
else if (version == '12.2(4)XF1')
  security_warning(0);
else if (version == '12.2(4)XF')
  security_warning(0);
else if (version == '12.2(2)XF2')
  security_warning(0);
else if (version == '12.2(2)XF1')
  security_warning(0);
else if (version == '12.2(2)XF')
  security_warning(0);
else if (version == '12.2(1)XF1')
  security_warning(0);
else if (version == '12.2(1)XF')
  security_warning(0);
else if (version == '12.2(1)XE2')
  security_warning(0);
else if (version == '12.2(1)XE1')
  security_warning(0);
else if (version == '12.2(1)XE')
  security_warning(0);
else if (version == '12.2(1)XD4')
  security_warning(0);
else if (version == '12.2(1)XD3')
  security_warning(0);
else if (version == '12.2(1)XD2')
  security_warning(0);
else if (version == '12.2(1)XD1')
  security_warning(0);
else if (version == '12.2(1)XD')
  security_warning(0);
else if (version == '12.2(2)XC2')
  security_warning(0);
else if (version == '12.2(2)XC1')
  security_warning(0);
else if (version == '12.2(2)XC')
  security_warning(0);
else if (version == '12.2(1a)XC3')
  security_warning(0);
else if (version == '12.2(1a)XC2')
  security_warning(0);
else if (version == '12.2(1a)XC1')
  security_warning(0);
else if (version == '12.2(1a)XC')
  security_warning(0);
else if (version == '12.2(2)XB8')
  security_warning(0);
else if (version == '12.2(2)XB7')
  security_warning(0);
else if (version == '12.2(2)XB6')
  security_warning(0);
else if (version == '12.2(2)XB5')
  security_warning(0);
else if (version == '12.2(2)XB3')
  security_warning(0);
else if (version == '12.2(2)XB2')
  security_warning(0);
else if (version == '12.2(2)XB15')
  security_warning(0);
else if (version == '12.2(2)XB14')
  security_warning(0);
else if (version == '12.2(2)XB12')
  security_warning(0);
else if (version == '12.2(2)XB11')
  security_warning(0);
else if (version == '12.2(2)XB10')
  security_warning(0);
else if (version == '12.2(2)XB1')
  security_warning(0);
else if (version == '12.2(2)XA5')
  security_warning(0);
else if (version == '12.2(2)XA4')
  security_warning(0);
else if (version == '12.2(2)XA3')
  security_warning(0);
else if (version == '12.2(2)XA2')
  security_warning(0);
else if (version == '12.2(2)XA1')
  security_warning(0);
else if (version == '12.2(2)XA')
  security_warning(0);
else if (version == '12.2(15)T9')
  security_warning(0);
else if (version == '12.2(15)T8')
  security_warning(0);
else if (version == '12.2(15)T7')
  security_warning(0);
else if (version == '12.2(15)T5')
  security_warning(0);
else if (version == '12.2(15)T4e')
  security_warning(0);
else if (version == '12.2(15)T4')
  security_warning(0);
else if (version == '12.2(15)T2')
  security_warning(0);
else if (version == '12.2(15)T14')
  security_warning(0);
else if (version == '12.2(15)T13')
  security_warning(0);
else if (version == '12.2(15)T12')
  security_warning(0);
else if (version == '12.2(15)T11')
  security_warning(0);
else if (version == '12.2(15)T10')
  security_warning(0);
else if (version == '12.2(15)T1')
  security_warning(0);
else if (version == '12.2(15)T')
  security_warning(0);
else if (version == '12.2(13)T9')
  security_warning(0);
else if (version == '12.2(13)T8')
  security_warning(0);
else if (version == '12.2(13)T5')
  security_warning(0);
else if (version == '12.2(13)T4')
  security_warning(0);
else if (version == '12.2(13)T3')
  security_warning(0);
else if (version == '12.2(13)T2')
  security_warning(0);
else if (version == '12.2(13)T13')
  security_warning(0);
else if (version == '12.2(13)T12')
  security_warning(0);
else if (version == '12.2(13)T11')
  security_warning(0);
else if (version == '12.2(13)T10')
  security_warning(0);
else if (version == '12.2(13)T1a')
  security_warning(0);
else if (version == '12.2(13)T1')
  security_warning(0);
else if (version == '12.2(13)T')
  security_warning(0);
else if (version == '12.2(11)T9')
  security_warning(0);
else if (version == '12.2(11)T8')
  security_warning(0);
else if (version == '12.2(11)T6')
  security_warning(0);
else if (version == '12.2(11)T5')
  security_warning(0);
else if (version == '12.2(11)T4')
  security_warning(0);
else if (version == '12.2(11)T3')
  security_warning(0);
else if (version == '12.2(11)T2')
  security_warning(0);
else if (version == '12.2(11)T11')
  security_warning(0);
else if (version == '12.2(11)T10')
  security_warning(0);
else if (version == '12.2(11)T1')
  security_warning(0);
else if (version == '12.2(11)T')
  security_warning(0);
else if (version == '12.2(8)T8')
  security_warning(0);
else if (version == '12.2(8)T7')
  security_warning(0);
else if (version == '12.2(8)T5')
  security_warning(0);
else if (version == '12.2(8)T4')
  security_warning(0);
else if (version == '12.2(8)T3')
  security_warning(0);
else if (version == '12.2(8)T2')
  security_warning(0);
else if (version == '12.2(8)T10')
  security_warning(0);
else if (version == '12.2(8)T1')
  security_warning(0);
else if (version == '12.2(8)T')
  security_warning(0);
else if (version == '12.2(4)T7')
  security_warning(0);
else if (version == '12.2(4)T6')
  security_warning(0);
else if (version == '12.2(4)T5')
  security_warning(0);
else if (version == '12.2(4)T3')
  security_warning(0);
else if (version == '12.2(4)T2')
  security_warning(0);
else if (version == '12.2(4)T1')
  security_warning(0);
else if (version == '12.2(4)T')
  security_warning(0);
else if (version == '12.2(2)T4')
  security_warning(0);
else if (version == '12.2(2)T3')
  security_warning(0);
else if (version == '12.2(2)T2')
  security_warning(0);
else if (version == '12.2(2)T1')
  security_warning(0);
else if (version == '12.2(2)T')
  security_warning(0);
else if (version == '12.2(14)SZ6')
  security_warning(0);
else if (version == '12.2(14)SZ5')
  security_warning(0);
else if (version == '12.2(14)SZ4')
  security_warning(0);
else if (version == '12.2(14)SZ3')
  security_warning(0);
else if (version == '12.2(14)SZ2')
  security_warning(0);
else if (version == '12.2(14)SZ1')
  security_warning(0);
else if (version == '12.2(14)SZ')
  security_warning(0);
else if (version == '12.2(14)SY5')
  security_warning(0);
else if (version == '12.2(14)SY4')
  security_warning(0);
else if (version == '12.2(14)SY3')
  security_warning(0);
else if (version == '12.2(14)SY2')
  security_warning(0);
else if (version == '12.2(14)SY1')
  security_warning(0);
else if (version == '12.2(14)SY')
  security_warning(0);
else if (version == '12.2(18)SXD')
  security_warning(0);
else if (version == '12.2(17d)SXB4')
  security_warning(0);
else if (version == '12.2(17d)SXB3')
  security_warning(0);
else if (version == '12.2(17d)SXB2')
  security_warning(0);
else if (version == '12.2(17d)SXB1')
  security_warning(0);
else if (version == '12.2(17d)SXB')
  security_warning(0);
else if (version == '12.2(17b)SXA2')
  security_warning(0);
else if (version == '12.2(17b)SXA')
  security_warning(0);
else if (version == '12.2(17a)SX4')
  security_warning(0);
else if (version == '12.2(17a)SX3')
  security_warning(0);
else if (version == '12.2(17a)SX2')
  security_warning(0);
else if (version == '12.2(17a)SX1')
  security_warning(0);
else if (version == '12.2(17a)SX')
  security_warning(0);
else if (version == '12.2(14)SX2')
  security_warning(0);
else if (version == '12.2(14)SX1')
  security_warning(0);
else if (version == '12.2(14)SX')
  security_warning(0);
else if (version == '12.2(25)SW4')
  security_warning(0);
else if (version == '12.2(25)SW3b')
  security_warning(0);
else if (version == '12.2(25)SW3a')
  security_warning(0);
else if (version == '12.2(25)SW3')
  security_warning(0);
else if (version == '12.2(25)SW2')
  security_warning(0);
else if (version == '12.2(25)SW1')
  security_warning(0);
else if (version == '12.2(25)SW')
  security_warning(0);
else if (version == '12.2(23)SW1')
  security_warning(0);
else if (version == '12.2(23)SW')
  security_warning(0);
else if (version == '12.2(21)SW1')
  security_warning(0);
else if (version == '12.2(21)SW')
  security_warning(0);
else if (version == '12.2(20)SW')
  security_warning(0);
else if (version == '12.2(19)SW')
  security_warning(0);
else if (version == '12.2(18)SW')
  security_warning(0);
else if (version == '12.2(23)SV1')
  security_warning(0);
else if (version == '12.2(23)SV')
  security_warning(0);
else if (version == '12.2(22)SV1')
  security_warning(0);
else if (version == '12.2(22)SV')
  security_warning(0);
else if (version == '12.2(18)SV3')
  security_warning(0);
else if (version == '12.2(18)SV2')
  security_warning(0);
else if (version == '12.2(18)SV1')
  security_warning(0);
else if (version == '12.2(18)SV')
  security_warning(0);
else if (version == '12.2(14)SU1')
  security_warning(0);
else if (version == '12.2(14)SU')
  security_warning(0);
else if (version == '12.2(20)SE2')
  security_warning(0);
else if (version == '12.2(20)SE1')
  security_warning(0);
else if (version == '12.2(20)SE')
  security_warning(0);
else if (version == '12.2(18)SE1')
  security_warning(0);
else if (version == '12.2(18)SE')
  security_warning(0);
else if (version == '12.2(25)S')
  security_warning(0);
else if (version == '12.2(22)S2')
  security_warning(0);
else if (version == '12.2(22)S1')
  security_warning(0);
else if (version == '12.2(22)S')
  security_warning(0);
else if (version == '12.2(20)S5')
  security_warning(0);
else if (version == '12.2(20)S4')
  security_warning(0);
else if (version == '12.2(20)S3')
  security_warning(0);
else if (version == '12.2(20)S2')
  security_warning(0);
else if (version == '12.2(20)S1')
  security_warning(0);
else if (version == '12.2(20)S')
  security_warning(0);
else if (version == '12.2(18)S5')
  security_warning(0);
else if (version == '12.2(18)S4')
  security_warning(0);
else if (version == '12.2(18)S3')
  security_warning(0);
else if (version == '12.2(18)S2')
  security_warning(0);
else if (version == '12.2(18)S1')
  security_warning(0);
else if (version == '12.2(18)S')
  security_warning(0);
else if (version == '12.2(14)S9')
  security_warning(0);
else if (version == '12.2(14)S8')
  security_warning(0);
else if (version == '12.2(14)S7')
  security_warning(0);
else if (version == '12.2(14)S5')
  security_warning(0);
else if (version == '12.2(14)S3')
  security_warning(0);
else if (version == '12.2(14)S2')
  security_warning(0);
else if (version == '12.2(14)S11')
  security_warning(0);
else if (version == '12.2(14)S10')
  security_warning(0);
else if (version == '12.2(14)S1')
  security_warning(0);
else if (version == '12.2(14)S')
  security_warning(0);
else if (version == '12.2(9)S')
  security_warning(0);
else if (version == '12.2(15)MC2c')
  security_warning(0);
else if (version == '12.2(15)MC2b')
  security_warning(0);
else if (version == '12.2(15)MC2a')
  security_warning(0);
else if (version == '12.2(15)MC2')
  security_warning(0);
else if (version == '12.2(15)MC1c')
  security_warning(0);
else if (version == '12.2(15)MC1b')
  security_warning(0);
else if (version == '12.2(15)MC1a')
  security_warning(0);
else if (version == '12.2(15)MC1')
  security_warning(0);
else if (version == '12.2(8)MC2d')
  security_warning(0);
else if (version == '12.2(8)MC2c')
  security_warning(0);
else if (version == '12.2(8)MC2b')
  security_warning(0);
else if (version == '12.2(8)MC2a')
  security_warning(0);
else if (version == '12.2(8)MC2')
  security_warning(0);
else if (version == '12.2(8)MC1')
  security_warning(0);
else if (version == '12.2(4)MB9a')
  security_warning(0);
else if (version == '12.2(4)MB9')
  security_warning(0);
else if (version == '12.2(4)MB8')
  security_warning(0);
else if (version == '12.2(4)MB7')
  security_warning(0);
else if (version == '12.2(4)MB6')
  security_warning(0);
else if (version == '12.2(4)MB5')
  security_warning(0);
else if (version == '12.2(4)MB4')
  security_warning(0);
else if (version == '12.2(4)MB3')
  security_warning(0);
else if (version == '12.2(4)MB2')
  security_warning(0);
else if (version == '12.2(4)MB13c')
  security_warning(0);
else if (version == '12.2(4)MB13b')
  security_warning(0);
else if (version == '12.2(4)MB13a')
  security_warning(0);
else if (version == '12.2(4)MB13')
  security_warning(0);
else if (version == '12.2(4)MB12')
  security_warning(0);
else if (version == '12.2(4)MB11')
  security_warning(0);
else if (version == '12.2(4)MB10')
  security_warning(0);
else if (version == '12.2(4)MB1')
  security_warning(0);
else if (version == '12.2(1)MB1')
  security_warning(0);
else if (version == '12.2(12h)M1')
  security_warning(0);
else if (version == '12.2(12b)M1')
  security_warning(0);
else if (version == '12.2(6c)M1')
  security_warning(0);
else if (version == '12.2(1)M0')
  security_warning(0);
else if (version == '12.2(15)JK1')
  security_warning(0);
else if (version == '12.2(15)JK')
  security_warning(0);
else if (version == '12.2(15)JA')
  security_warning(0);
else if (version == '12.2(13)JA4')
  security_warning(0);
else if (version == '12.2(13)JA3')
  security_warning(0);
else if (version == '12.2(13)JA2')
  security_warning(0);
else if (version == '12.2(13)JA1')
  security_warning(0);
else if (version == '12.2(13)JA')
  security_warning(0);
else if (version == '12.2(11)JA3')
  security_warning(0);
else if (version == '12.2(11)JA2')
  security_warning(0);
else if (version == '12.2(11)JA1')
  security_warning(0);
else if (version == '12.2(11)JA')
  security_warning(0);
else if (version == '12.2(8)JA')
  security_warning(0);
else if (version == '12.2(4)JA1')
  security_warning(0);
else if (version == '12.2(4)JA')
  security_warning(0);
else if (version == '12.2(20)EWA4')
  security_warning(0);
else if (version == '12.2(20)EWA3')
  security_warning(0);
else if (version == '12.2(20)EWA2')
  security_warning(0);
else if (version == '12.2(20)EWA1')
  security_warning(0);
else if (version == '12.2(20)EWA')
  security_warning(0);
else if (version == '12.2(20)EW4')
  security_warning(0);
else if (version == '12.2(20)EW3')
  security_warning(0);
else if (version == '12.2(20)EW2')
  security_warning(0);
else if (version == '12.2(20)EW1')
  security_warning(0);
else if (version == '12.2(20)EW')
  security_warning(0);
else if (version == '12.2(18)EW1')
  security_warning(0);
else if (version == '12.2(18)EW')
  security_warning(0);
else if (version == '12.2(20)EU2')
  security_warning(0);
else if (version == '12.2(20)EU1')
  security_warning(0);
else if (version == '12.2(20)EU')
  security_warning(0);
else if (version == '12.2(2)DX3')
  security_warning(0);
else if (version == '12.2(1)DX1')
  security_warning(0);
else if (version == '12.2(1)DX')
  security_warning(0);
else if (version == '12.2(2)DD4')
  security_warning(0);
else if (version == '12.2(2)DD3')
  security_warning(0);
else if (version == '12.2(2)DD2')
  security_warning(0);
else if (version == '12.2(2)DD1')
  security_warning(0);
else if (version == '12.2(2)DD')
  security_warning(0);
else if (version == '12.2(12)DA8')
  security_warning(0);
else if (version == '12.2(12)DA7')
  security_warning(0);
else if (version == '12.2(12)DA6')
  security_warning(0);
else if (version == '12.2(12)DA5')
  security_warning(0);
else if (version == '12.2(12)DA4')
  security_warning(0);
else if (version == '12.2(12)DA3')
  security_warning(0);
else if (version == '12.2(12)DA2')
  security_warning(0);
else if (version == '12.2(12)DA1')
  security_warning(0);
else if (version == '12.2(12)DA')
  security_warning(0);
else if (version == '12.2(10)DA3')
  security_warning(0);
else if (version == '12.2(10)DA2')
  security_warning(0);
else if (version == '12.2(10)DA1')
  security_warning(0);
else if (version == '12.2(10)DA')
  security_warning(0);
else if (version == '12.2(7)DA')
  security_warning(0);
else if (version == '12.2(5)DA1')
  security_warning(0);
else if (version == '12.2(5)DA')
  security_warning(0);
else if (version == '12.2(1b)DA1')
  security_warning(0);
else if (version == '12.2(1b)DA')
  security_warning(0);
else if (version == '12.2(15)CZ')
  security_warning(0);
else if (version == '12.2(11)CY')
  security_warning(0);
else if (version == '12.2(15)CX1')
  security_warning(0);
else if (version == '12.2(15)CX')
  security_warning(0);
else if (version == '12.2(11)CX1')
  security_warning(0);
else if (version == '12.2(11)CX')
  security_warning(0);
else if (version == '12.2(15)BZ2')
  security_warning(0);
else if (version == '12.2(4)BZ2')
  security_warning(0);
else if (version == '12.2(4)BZ1')
  security_warning(0);
else if (version == '12.2(8)BY2')
  security_warning(0);
else if (version == '12.2(8)BY1')
  security_warning(0);
else if (version == '12.2(8)BY')
  security_warning(0);
else if (version == '12.2(2)BY3')
  security_warning(0);
else if (version == '12.2(2)BY2')
  security_warning(0);
else if (version == '12.2(2)BY1')
  security_warning(0);
else if (version == '12.2(2)BY')
  security_warning(0);
else if (version == '12.2(16)BX3')
  security_warning(0);
else if (version == '12.2(16)BX2')
  security_warning(0);
else if (version == '12.2(16)BX1')
  security_warning(0);
else if (version == '12.2(16)BX')
  security_warning(0);
else if (version == '12.2(15)BX')
  security_warning(0);
else if (version == '12.2(2)BX1')
  security_warning(0);
else if (version == '12.2(2)BX')
  security_warning(0);
else if (version == '12.2(4)BW2')
  security_warning(0);
else if (version == '12.2(4)BW1a')
  security_warning(0);
else if (version == '12.2(4)BW1')
  security_warning(0);
else if (version == '12.2(4)BW')
  security_warning(0);
else if (version == '12.2(15)BC2d')
  security_warning(0);
else if (version == '12.2(15)BC2c')
  security_warning(0);
else if (version == '12.2(15)BC2b')
  security_warning(0);
else if (version == '12.2(15)BC2a')
  security_warning(0);
else if (version == '12.2(15)BC2')
  security_warning(0);
else if (version == '12.2(15)BC1e')
  security_warning(0);
else if (version == '12.2(15)BC1d')
  security_warning(0);
else if (version == '12.2(15)BC1c')
  security_warning(0);
else if (version == '12.2(15)BC1b')
  security_warning(0);
else if (version == '12.2(15)BC1a')
  security_warning(0);
else if (version == '12.2(15)BC1')
  security_warning(0);
else if (version == '12.2(11)BC3d')
  security_warning(0);
else if (version == '12.2(11)BC3c')
  security_warning(0);
else if (version == '12.2(11)BC3b')
  security_warning(0);
else if (version == '12.2(11)BC3a')
  security_warning(0);
else if (version == '12.2(11)BC3')
  security_warning(0);
else if (version == '12.2(11)BC2a')
  security_warning(0);
else if (version == '12.2(11)BC2')
  security_warning(0);
else if (version == '12.2(11)BC1b')
  security_warning(0);
else if (version == '12.2(11)BC1a')
  security_warning(0);
else if (version == '12.2(11)BC1')
  security_warning(0);
else if (version == '12.2(8)BC2a')
  security_warning(0);
else if (version == '12.2(8)BC2')
  security_warning(0);
else if (version == '12.2(8)BC1')
  security_warning(0);
else if (version == '12.2(4)BC1b')
  security_warning(0);
else if (version == '12.2(4)BC1a')
  security_warning(0);
else if (version == '12.2(4)BC1')
  security_warning(0);
else if (version == '12.2(16)B2')
  security_warning(0);
else if (version == '12.2(16)B1')
  security_warning(0);
else if (version == '12.2(16)B')
  security_warning(0);
else if (version == '12.2(15)B')
  security_warning(0);
else if (version == '12.2(4)B8')
  security_warning(0);
else if (version == '12.2(4)B7')
  security_warning(0);
else if (version == '12.2(4)B6')
  security_warning(0);
else if (version == '12.2(4)B5')
  security_warning(0);
else if (version == '12.2(4)B4')
  security_warning(0);
else if (version == '12.2(4)B3')
  security_warning(0);
else if (version == '12.2(4)B2')
  security_warning(0);
else if (version == '12.2(4)B1')
  security_warning(0);
else if (version == '12.2(4)B')
  security_warning(0);
else if (version == '12.2(2)B7')
  security_warning(0);
else if (version == '12.2(2)B6')
  security_warning(0);
else if (version == '12.2(2)B5')
  security_warning(0);
else if (version == '12.2(2)B4')
  security_warning(0);
else if (version == '12.2(2)B3')
  security_warning(0);
else if (version == '12.2(2)B2')
  security_warning(0);
else if (version == '12.2(2)B1')
  security_warning(0);
else if (version == '12.2(2)B')
  security_warning(0);
else if (version == '12.2(26)')
  security_warning(0);
else if (version == '12.2(24b)')
  security_warning(0);
else if (version == '12.2(24a)')
  security_warning(0);
else if (version == '12.2(24)')
  security_warning(0);
else if (version == '12.2(23d)')
  security_warning(0);
else if (version == '12.2(23c)')
  security_warning(0);
else if (version == '12.2(23a)')
  security_warning(0);
else if (version == '12.2(23)')
  security_warning(0);
else if (version == '12.2(21b)')
  security_warning(0);
else if (version == '12.2(21a)')
  security_warning(0);
else if (version == '12.2(21)')
  security_warning(0);
else if (version == '12.2(19c)')
  security_warning(0);
else if (version == '12.2(19b)')
  security_warning(0);
else if (version == '12.2(19a)')
  security_warning(0);
else if (version == '12.2(19)')
  security_warning(0);
else if (version == '12.2(17d)')
  security_warning(0);
else if (version == '12.2(17b)')
  security_warning(0);
else if (version == '12.2(17a)')
  security_warning(0);
else if (version == '12.2(17)')
  security_warning(0);
else if (version == '12.2(16f)')
  security_warning(0);
else if (version == '12.2(16c)')
  security_warning(0);
else if (version == '12.2(16b)')
  security_warning(0);
else if (version == '12.2(16a)')
  security_warning(0);
else if (version == '12.2(16)')
  security_warning(0);
else if (version == '12.2(13e)')
  security_warning(0);
else if (version == '12.2(13c)')
  security_warning(0);
else if (version == '12.2(13b)')
  security_warning(0);
else if (version == '12.2(13a)')
  security_warning(0);
else if (version == '12.2(13)')
  security_warning(0);
else if (version == '12.2(12j)')
  security_warning(0);
else if (version == '12.2(12i)')
  security_warning(0);
else if (version == '12.2(12h)')
  security_warning(0);
else if (version == '12.2(12g)')
  security_warning(0);
else if (version == '12.2(12f)')
  security_warning(0);
else if (version == '12.2(12e)')
  security_warning(0);
else if (version == '12.2(12c)')
  security_warning(0);
else if (version == '12.2(12b)')
  security_warning(0);
else if (version == '12.2(12a)')
  security_warning(0);
else if (version == '12.2(12)')
  security_warning(0);
else if (version == '12.2(10g)')
  security_warning(0);
else if (version == '12.2(10d)')
  security_warning(0);
else if (version == '12.2(10b)')
  security_warning(0);
else if (version == '12.2(10a)')
  security_warning(0);
else if (version == '12.2(10)')
  security_warning(0);
else if (version == '12.2(7g)')
  security_warning(0);
else if (version == '12.2(7e)')
  security_warning(0);
else if (version == '12.2(7c)')
  security_warning(0);
else if (version == '12.2(7b)')
  security_warning(0);
else if (version == '12.2(7a)')
  security_warning(0);
else if (version == '12.2(7)')
  security_warning(0);
else if (version == '12.2(6j)')
  security_warning(0);
else if (version == '12.2(6i)')
  security_warning(0);
else if (version == '12.2(6h)')
  security_warning(0);
else if (version == '12.2(6g)')
  security_warning(0);
else if (version == '12.2(6f)')
  security_warning(0);
else if (version == '12.2(6e)')
  security_warning(0);
else if (version == '12.2(6d)')
  security_warning(0);
else if (version == '12.2(6c)')
  security_warning(0);
else if (version == '12.2(6b)')
  security_warning(0);
else if (version == '12.2(6a)')
  security_warning(0);
else if (version == '12.2(6)')
  security_warning(0);
else if (version == '12.2(5d)')
  security_warning(0);
else if (version == '12.2(5c)')
  security_warning(0);
else if (version == '12.2(5b)')
  security_warning(0);
else if (version == '12.2(5a)')
  security_warning(0);
else if (version == '12.2(5)')
  security_warning(0);
else if (version == '12.2(3g)')
  security_warning(0);
else if (version == '12.2(3d)')
  security_warning(0);
else if (version == '12.2(3c)')
  security_warning(0);
else if (version == '12.2(3b)')
  security_warning(0);
else if (version == '12.2(3a)')
  security_warning(0);
else if (version == '12.2(3)')
  security_warning(0);
else if (version == '12.2(1d)')
  security_warning(0);
else if (version == '12.2(1c)')
  security_warning(0);
else if (version == '12.2(1b)')
  security_warning(0);
else if (version == '12.2(1a)')
  security_warning(0);
else if (version == '12.2(1)')
  security_warning(0);
else if (version == '12.1(11)YJ4')
  security_warning(0);
else if (version == '12.1(11)YJ3')
  security_warning(0);
else if (version == '12.1(11)YJ2')
  security_warning(0);
else if (version == '12.1(11)YJ')
  security_warning(0);
else if (version == '12.1(5)YI2')
  security_warning(0);
else if (version == '12.1(5)YI1')
  security_warning(0);
else if (version == '12.1(5)YI')
  security_warning(0);
else if (version == '12.1(5)YH4')
  security_warning(0);
else if (version == '12.1(5)YH3')
  security_warning(0);
else if (version == '12.1(5)YH2')
  security_warning(0);
else if (version == '12.1(5)YH1')
  security_warning(0);
else if (version == '12.1(5)YH')
  security_warning(0);
else if (version == '12.1(5)YF4')
  security_warning(0);
else if (version == '12.1(5)YF3')
  security_warning(0);
else if (version == '12.1(5)YF2')
  security_warning(0);
else if (version == '12.1(5)YF1')
  security_warning(0);
else if (version == '12.1(5)YF')
  security_warning(0);
else if (version == '12.1(5)YE5')
  security_warning(0);
else if (version == '12.1(5)YE4')
  security_warning(0);
else if (version == '12.1(5)YE3')
  security_warning(0);
else if (version == '12.1(5)YE2')
  security_warning(0);
else if (version == '12.1(5)YE1')
  security_warning(0);
else if (version == '12.1(5)YD6')
  security_warning(0);
else if (version == '12.1(5)YD5')
  security_warning(0);
else if (version == '12.1(5)YD4')
  security_warning(0);
else if (version == '12.1(5)YD3')
  security_warning(0);
else if (version == '12.1(5)YD2')
  security_warning(0);
else if (version == '12.1(5)YD1')
  security_warning(0);
else if (version == '12.1(5)YD')
  security_warning(0);
else if (version == '12.1(5)YC3')
  security_warning(0);
else if (version == '12.1(5)YC2')
  security_warning(0);
else if (version == '12.1(5)YC1')
  security_warning(0);
else if (version == '12.1(5)YC')
  security_warning(0);
else if (version == '12.1(5)YB5')
  security_warning(0);
else if (version == '12.1(5)YB4')
  security_warning(0);
else if (version == '12.1(5)YB3')
  security_warning(0);
else if (version == '12.1(5)YB1')
  security_warning(0);
else if (version == '12.1(5)YB')
  security_warning(0);
else if (version == '12.1(5)YA2')
  security_warning(0);
else if (version == '12.1(5)YA1')
  security_warning(0);
else if (version == '12.1(5)YA')
  security_warning(0);
else if (version == '12.1(4)XZ7')
  security_warning(0);
else if (version == '12.1(4)XZ6')
  security_warning(0);
else if (version == '12.1(4)XZ5')
  security_warning(0);
else if (version == '12.1(4)XZ4')
  security_warning(0);
else if (version == '12.1(4)XZ3')
  security_warning(0);
else if (version == '12.1(4)XZ2')
  security_warning(0);
else if (version == '12.1(4)XZ1')
  security_warning(0);
else if (version == '12.1(4)XZ')
  security_warning(0);
else if (version == '12.1(4)XY8')
  security_warning(0);
else if (version == '12.1(4)XY7')
  security_warning(0);
else if (version == '12.1(4)XY6')
  security_warning(0);
else if (version == '12.1(4)XY5')
  security_warning(0);
else if (version == '12.1(4)XY4')
  security_warning(0);
else if (version == '12.1(4)XY3')
  security_warning(0);
else if (version == '12.1(4)XY2')
  security_warning(0);
else if (version == '12.1(4)XY1')
  security_warning(0);
else if (version == '12.1(4)XY')
  security_warning(0);
else if (version == '12.1(5)XX3')
  security_warning(0);
else if (version == '12.1(5)XX2')
  security_warning(0);
else if (version == '12.1(5)XX1')
  security_warning(0);
else if (version == '12.1(5)XX')
  security_warning(0);
else if (version == '12.1(3)XW2')
  security_warning(0);
else if (version == '12.1(3)XW1')
  security_warning(0);
else if (version == '12.1(3)XW')
  security_warning(0);
else if (version == '12.1(5)XV4')
  security_warning(0);
else if (version == '12.1(5)XV3')
  security_warning(0);
else if (version == '12.1(5)XV2')
  security_warning(0);
else if (version == '12.1(5)XV1')
  security_warning(0);
else if (version == '12.1(5)XV')
  security_warning(0);
else if (version == '12.1(5)XU1')
  security_warning(0);
else if (version == '12.1(5)XU')
  security_warning(0);
else if (version == '12.1(3)XT2')
  security_warning(0);
else if (version == '12.1(3)XT1')
  security_warning(0);
else if (version == '12.1(3)XT')
  security_warning(0);
else if (version == '12.1(2)XT2')
  security_warning(0);
else if (version == '12.1(5)XS5')
  security_warning(0);
else if (version == '12.1(5)XS4')
  security_warning(0);
else if (version == '12.1(5)XS3')
  security_warning(0);
else if (version == '12.1(5)XS2')
  security_warning(0);
else if (version == '12.1(5)XS1')
  security_warning(0);
else if (version == '12.1(5)XS')
  security_warning(0);
else if (version == '12.1(3)XS')
  security_warning(0);
else if (version == '12.1(5)XR2')
  security_warning(0);
else if (version == '12.1(5)XR1')
  security_warning(0);
else if (version == '12.1(5)XR')
  security_warning(0);
else if (version == '12.1(3)XQ3')
  security_warning(0);
else if (version == '12.1(3)XQ2')
  security_warning(0);
else if (version == '12.1(3)XQ1')
  security_warning(0);
else if (version == '12.1(3)XQ')
  security_warning(0);
else if (version == '12.1(3)XP4')
  security_warning(0);
else if (version == '12.1(3)XP3')
  security_warning(0);
else if (version == '12.1(3)XP2')
  security_warning(0);
else if (version == '12.1(3)XP1')
  security_warning(0);
else if (version == '12.1(3)XP')
  security_warning(0);
else if (version == '12.1(5)XM8')
  security_warning(0);
else if (version == '12.1(5)XM7')
  security_warning(0);
else if (version == '12.1(5)XM6')
  security_warning(0);
else if (version == '12.1(5)XM5')
  security_warning(0);
else if (version == '12.1(5)XM4')
  security_warning(0);
else if (version == '12.1(5)XM3')
  security_warning(0);
else if (version == '12.1(5)XM2')
  security_warning(0);
else if (version == '12.1(5)XM1')
  security_warning(0);
else if (version == '12.1(5)XM')
  security_warning(0);
else if (version == '12.1(3a)XL3')
  security_warning(0);
else if (version == '12.1(3a)XL2')
  security_warning(0);
else if (version == '12.1(3a)XL1')
  security_warning(0);
else if (version == '12.1(3)XL')
  security_warning(0);
else if (version == '12.1(3)XJ')
  security_warning(0);
else if (version == '12.1(3a)XI9')
  security_warning(0);
else if (version == '12.1(3a)XI8')
  security_warning(0);
else if (version == '12.1(3a)XI7')
  security_warning(0);
else if (version == '12.1(3a)XI6')
  security_warning(0);
else if (version == '12.1(3a)XI5')
  security_warning(0);
else if (version == '12.1(3a)XI4')
  security_warning(0);
else if (version == '12.1(3a)XI3')
  security_warning(0);
else if (version == '12.1(3a)XI2')
  security_warning(0);
else if (version == '12.1(3a)XI1')
  security_warning(0);
else if (version == '12.1(3)XI')
  security_warning(0);
else if (version == '12.1(2a)XH3')
  security_warning(0);
else if (version == '12.1(2a)XH2')
  security_warning(0);
else if (version == '12.1(2a)XH1')
  security_warning(0);
else if (version == '12.1(2a)XH')
  security_warning(0);
else if (version == '12.1(3)XG6')
  security_warning(0);
else if (version == '12.1(3)XG5')
  security_warning(0);
else if (version == '12.1(3)XG4')
  security_warning(0);
else if (version == '12.1(3)XG3')
  security_warning(0);
else if (version == '12.1(3)XG2')
  security_warning(0);
else if (version == '12.1(3)XG1')
  security_warning(0);
else if (version == '12.1(3)XG')
  security_warning(0);
else if (version == '12.1(2)XF5')
  security_warning(0);
else if (version == '12.1(2)XF4')
  security_warning(0);
else if (version == '12.1(2)XF3')
  security_warning(0);
else if (version == '12.1(2)XF2')
  security_warning(0);
else if (version == '12.1(2)XF1')
  security_warning(0);
else if (version == '12.1(2)XF')
  security_warning(0);
else if (version == '12.1(1)XE1')
  security_warning(0);
else if (version == '12.1(1)XE')
  security_warning(0);
else if (version == '12.1(1)XD2')
  security_warning(0);
else if (version == '12.1(1)XD1')
  security_warning(0);
else if (version == '12.1(1)XD')
  security_warning(0);
else if (version == '12.1(1)XC1')
  security_warning(0);
else if (version == '12.1(1)XB')
  security_warning(0);
else if (version == '12.1(1)XA4')
  security_warning(0);
else if (version == '12.1(1)XA3')
  security_warning(0);
else if (version == '12.1(1)XA2')
  security_warning(0);
else if (version == '12.1(1)XA')
  security_warning(0);
else if (version == '12.1(5)T9')
  security_warning(0);
else if (version == '12.1(5)T8b')
  security_warning(0);
else if (version == '12.1(5)T8a')
  security_warning(0);
else if (version == '12.1(5)T8')
  security_warning(0);
else if (version == '12.1(5)T7')
  security_warning(0);
else if (version == '12.1(5)T6')
  security_warning(0);
else if (version == '12.1(5)T5')
  security_warning(0);
else if (version == '12.1(5)T4')
  security_warning(0);
else if (version == '12.1(5)T3')
  security_warning(0);
else if (version == '12.1(5)T20')
  security_warning(0);
else if (version == '12.1(5)T2')
  security_warning(0);
else if (version == '12.1(5)T19')
  security_warning(0);
else if (version == '12.1(5)T18')
  security_warning(0);
else if (version == '12.1(5)T17')
  security_warning(0);
else if (version == '12.1(5)T15')
  security_warning(0);
else if (version == '12.1(5)T14')
  security_warning(0);
else if (version == '12.1(5)T12')
  security_warning(0);
else if (version == '12.1(5)T11')
  security_warning(0);
else if (version == '12.1(5)T10')
  security_warning(0);
else if (version == '12.1(5)T1')
  security_warning(0);
else if (version == '12.1(5)T')
  security_warning(0);
else if (version == '12.1(3a)T8')
  security_warning(0);
else if (version == '12.1(3a)T7')
  security_warning(0);
else if (version == '12.1(3a)T6')
  security_warning(0);
else if (version == '12.1(3a)T5')
  security_warning(0);
else if (version == '12.1(3a)T4')
  security_warning(0);
else if (version == '12.1(3a)T3')
  security_warning(0);
else if (version == '12.1(3a)T2')
  security_warning(0);
else if (version == '12.1(3a)T1')
  security_warning(0);
else if (version == '12.1(3)T')
  security_warning(0);
else if (version == '12.1(2a)T2')
  security_warning(0);
else if (version == '12.1(2a)T1')
  security_warning(0);
else if (version == '12.1(2)T')
  security_warning(0);
else if (version == '12.1(1a)T1')
  security_warning(0);
else if (version == '12.1(1)T')
  security_warning(0);
else if (version == '12.1(2)GB')
  security_warning(0);
else if (version == '12.1(1)GA1')
  security_warning(0);
else if (version == '12.1(1)GA')
  security_warning(0);
else if (version == '12.1(6)EZ6')
  security_warning(0);
else if (version == '12.1(6)EZ5')
  security_warning(0);
else if (version == '12.1(6)EZ4')
  security_warning(0);
else if (version == '12.1(6)EZ3')
  security_warning(0);
else if (version == '12.1(6)EZ2')
  security_warning(0);
else if (version == '12.1(6)EZ1')
  security_warning(0);
else if (version == '12.1(6)EZ')
  security_warning(0);
else if (version == '12.1(12c)EY')
  security_warning(0);
else if (version == '12.1(10)EY')
  security_warning(0);
else if (version == '12.1(7a)EY3')
  security_warning(0);
else if (version == '12.1(7a)EY2')
  security_warning(0);
else if (version == '12.1(7a)EY1')
  security_warning(0);
else if (version == '12.1(7a)EY')
  security_warning(0);
else if (version == '12.1(6)EY1')
  security_warning(0);
else if (version == '12.1(6)EY')
  security_warning(0);
else if (version == '12.1(5)EY2')
  security_warning(0);
else if (version == '12.1(5)EY1')
  security_warning(0);
else if (version == '12.1(5)EY')
  security_warning(0);
else if (version == '12.1(13)EX3')
  security_warning(0);
else if (version == '12.1(13)EX2')
  security_warning(0);
else if (version == '12.1(13)EX1')
  security_warning(0);
else if (version == '12.1(13)EX')
  security_warning(0);
else if (version == '12.1(12c)EX1')
  security_warning(0);
else if (version == '12.1(12c)EX')
  security_warning(0);
else if (version == '12.1(11b)EX1')
  security_warning(0);
else if (version == '12.1(11b)EX')
  security_warning(0);
else if (version == '12.1(10)EX2')
  security_warning(0);
else if (version == '12.1(10)EX1')
  security_warning(0);
else if (version == '12.1(10)EX')
  security_warning(0);
else if (version == '12.1(9)EX3')
  security_warning(0);
else if (version == '12.1(9)EX2')
  security_warning(0);
else if (version == '12.1(9)EX1')
  security_warning(0);
else if (version == '12.1(9)EX')
  security_warning(0);
else if (version == '12.1(8b)EX5')
  security_warning(0);
else if (version == '12.1(8b)EX4')
  security_warning(0);
else if (version == '12.1(8b)EX3')
  security_warning(0);
else if (version == '12.1(8b)EX2')
  security_warning(0);
else if (version == '12.1(8a)EX1')
  security_warning(0);
else if (version == '12.1(8a)EX')
  security_warning(0);
else if (version == '12.1(5c)EX3')
  security_warning(0);
else if (version == '12.1(1)EX1')
  security_warning(0);
else if (version == '12.1(1)EX')
  security_warning(0);
else if (version == '12.1(20)EW4')
  security_warning(0);
else if (version == '12.1(20)EW3')
  security_warning(0);
else if (version == '12.1(20)EW2')
  security_warning(0);
else if (version == '12.1(20)EW1')
  security_warning(0);
else if (version == '12.1(20)EW')
  security_warning(0);
else if (version == '12.1(19)EW3')
  security_warning(0);
else if (version == '12.1(19)EW2')
  security_warning(0);
else if (version == '12.1(19)EW1')
  security_warning(0);
else if (version == '12.1(19)EW')
  security_warning(0);
else if (version == '12.1(13)EW4')
  security_warning(0);
else if (version == '12.1(13)EW3')
  security_warning(0);
else if (version == '12.1(13)EW2')
  security_warning(0);
else if (version == '12.1(13)EW1')
  security_warning(0);
else if (version == '12.1(13)EW')
  security_warning(0);
else if (version == '12.1(12c)EW4')
  security_warning(0);
else if (version == '12.1(12c)EW3')
  security_warning(0);
else if (version == '12.1(12c)EW2')
  security_warning(0);
else if (version == '12.1(12c)EW1')
  security_warning(0);
else if (version == '12.1(12c)EW')
  security_warning(0);
else if (version == '12.1(11b)EW1')
  security_warning(0);
else if (version == '12.1(11b)EW')
  security_warning(0);
else if (version == '12.1(8a)EW1')
  security_warning(0);
else if (version == '12.1(8a)EW')
  security_warning(0);
else if (version == '12.1(12c)EV3')
  security_warning(0);
else if (version == '12.1(12c)EV2')
  security_warning(0);
else if (version == '12.1(12c)EV1')
  security_warning(0);
else if (version == '12.1(12c)EV')
  security_warning(0);
else if (version == '12.1(10)EV4')
  security_warning(0);
else if (version == '12.1(10)EV3')
  security_warning(0);
else if (version == '12.1(10)EV2')
  security_warning(0);
else if (version == '12.1(10)EV1a')
  security_warning(0);
else if (version == '12.1(10)EV1')
  security_warning(0);
else if (version == '12.1(10)EV')
  security_warning(0);
else if (version == '12.1(20)EU1')
  security_warning(0);
else if (version == '12.1(20)EU')
  security_warning(0);
else if (version == '12.1(20)EO2')
  security_warning(0);
else if (version == '12.1(20)EO1')
  security_warning(0);
else if (version == '12.1(20)EO')
  security_warning(0);
else if (version == '12.1(19)EO3')
  security_warning(0);
else if (version == '12.1(19)EO2')
  security_warning(0);
else if (version == '12.1(19)EO1')
  security_warning(0);
else if (version == '12.1(19)EO')
  security_warning(0);
else if (version == '12.1(14)EO1')
  security_warning(0);
else if (version == '12.1(14)EO')
  security_warning(0);
else if (version == '12.1(22)EC1')
  security_warning(0);
else if (version == '12.1(22)EC')
  security_warning(0);
else if (version == '12.1(20)EC3')
  security_warning(0);
else if (version == '12.1(20)EC2')
  security_warning(0);
else if (version == '12.1(20)EC1')
  security_warning(0);
else if (version == '12.1(20)EC')
  security_warning(0);
else if (version == '12.1(19)EC1')
  security_warning(0);
else if (version == '12.1(19)EC')
  security_warning(0);
else if (version == '12.1(13)EC4')
  security_warning(0);
else if (version == '12.1(13)EC3')
  security_warning(0);
else if (version == '12.1(13)EC2')
  security_warning(0);
else if (version == '12.1(13)EC1')
  security_warning(0);
else if (version == '12.1(13)EC')
  security_warning(0);
else if (version == '12.1(12c)EC1')
  security_warning(0);
else if (version == '12.1(12c)EC')
  security_warning(0);
else if (version == '12.1(11b)EC1')
  security_warning(0);
else if (version == '12.1(11b)EC')
  security_warning(0);
else if (version == '12.1(10)EC1')
  security_warning(0);
else if (version == '12.1(10)EC')
  security_warning(0);
else if (version == '12.1(9)EC1')
  security_warning(0);
else if (version == '12.1(9)EC')
  security_warning(0);
else if (version == '12.1(8)EC1')
  security_warning(0);
else if (version == '12.1(8)EC')
  security_warning(0);
else if (version == '12.1(7)EC')
  security_warning(0);
else if (version == '12.1(6)EC1')
  security_warning(0);
else if (version == '12.1(6)EC')
  security_warning(0);
else if (version == '12.1(5)EC1')
  security_warning(0);
else if (version == '12.1(5)EC')
  security_warning(0);
else if (version == '12.1(4)EC')
  security_warning(0);
else if (version == '12.1(3a)EC1')
  security_warning(0);
else if (version == '12.1(3a)EC')
  security_warning(0);
else if (version == '12.1(2)EC1')
  security_warning(0);
else if (version == '12.1(2)EC')
  security_warning(0);
else if (version == '12.1(22)EB')
  security_warning(0);
else if (version == '12.1(20)EB')
  security_warning(0);
else if (version == '12.1(19)EB')
  security_warning(0);
else if (version == '12.1(14)EB1')
  security_warning(0);
else if (version == '12.1(14)EB')
  security_warning(0);
else if (version == '12.1(13)EB1')
  security_warning(0);
else if (version == '12.1(13)EB')
  security_warning(0);
else if (version == '12.1(22)EA1b')
  security_warning(0);
else if (version == '12.1(22)EA1a')
  security_warning(0);
else if (version == '12.1(22)EA1')
  security_warning(0);
else if (version == '12.1(20)EA2')
  security_warning(0);
else if (version == '12.1(20)EA1a')
  security_warning(0);
else if (version == '12.1(20)EA1')
  security_warning(0);
else if (version == '12.1(19)EA1d')
  security_warning(0);
else if (version == '12.1(19)EA1c')
  security_warning(0);
else if (version == '12.1(19)EA1b')
  security_warning(0);
else if (version == '12.1(19)EA1a')
  security_warning(0);
else if (version == '12.1(19)EA1')
  security_warning(0);
else if (version == '12.1(14)EA1b')
  security_warning(0);
else if (version == '12.1(14)EA1a')
  security_warning(0);
else if (version == '12.1(14)EA1')
  security_warning(0);
else if (version == '12.1(13)EA1c')
  security_warning(0);
else if (version == '12.1(13)EA1b')
  security_warning(0);
else if (version == '12.1(13)EA1a')
  security_warning(0);
else if (version == '12.1(13)EA1')
  security_warning(0);
else if (version == '12.1(12c)EA1a')
  security_warning(0);
else if (version == '12.1(12c)EA1')
  security_warning(0);
else if (version == '12.1(11)EA1a')
  security_warning(0);
else if (version == '12.1(11)EA1')
  security_warning(0);
else if (version == '12.1(9)EA1')
  security_warning(0);
else if (version == '12.1(8)EA1c')
  security_warning(0);
else if (version == '12.1(6)EA1')
  security_warning(0);
else if (version == '12.1(4)EA1e')
  security_warning(0);
else if (version == '12.1(23)E')
  security_warning(0);
else if (version == '12.1(22)E2')
  security_warning(0);
else if (version == '12.1(22)E1')
  security_warning(0);
else if (version == '12.1(22)E')
  security_warning(0);
else if (version == '12.1(20)E4')
  security_warning(0);
else if (version == '12.1(20)E3')
  security_warning(0);
else if (version == '12.1(20)E2')
  security_warning(0);
else if (version == '12.1(20)E1')
  security_warning(0);
else if (version == '12.1(20)E')
  security_warning(0);
else if (version == '12.1(19)E7')
  security_warning(0);
else if (version == '12.1(19)E6')
  security_warning(0);
else if (version == '12.1(19)E4')
  security_warning(0);
else if (version == '12.1(19)E3')
  security_warning(0);
else if (version == '12.1(19)E2')
  security_warning(0);
else if (version == '12.1(19)E1')
  security_warning(0);
else if (version == '12.1(19)E')
  security_warning(0);
else if (version == '12.1(14)E7')
  security_warning(0);
else if (version == '12.1(14)E6')
  security_warning(0);
else if (version == '12.1(14)E5')
  security_warning(0);
else if (version == '12.1(14)E4')
  security_warning(0);
else if (version == '12.1(14)E3')
  security_warning(0);
else if (version == '12.1(14)E2')
  security_warning(0);
else if (version == '12.1(14)E10')
  security_warning(0);
else if (version == '12.1(14)E1')
  security_warning(0);
else if (version == '12.1(14)E')
  security_warning(0);
else if (version == '12.1(13)E9')
  security_warning(0);
else if (version == '12.1(13)E8')
  security_warning(0);
else if (version == '12.1(13)E7')
  security_warning(0);
else if (version == '12.1(13)E6')
  security_warning(0);
else if (version == '12.1(13)E5')
  security_warning(0);
else if (version == '12.1(13)E4')
  security_warning(0);
else if (version == '12.1(13)E3')
  security_warning(0);
else if (version == '12.1(13)E2')
  security_warning(0);
else if (version == '12.1(13)E15')
  security_warning(0);
else if (version == '12.1(13)E14')
  security_warning(0);
else if (version == '12.1(13)E13')
  security_warning(0);
else if (version == '12.1(13)E12')
  security_warning(0);
else if (version == '12.1(13)E11')
  security_warning(0);
else if (version == '12.1(13)E10')
  security_warning(0);
else if (version == '12.1(13)E1')
  security_warning(0);
else if (version == '12.1(13)E')
  security_warning(0);
else if (version == '12.1(12c)E6')
  security_warning(0);
else if (version == '12.1(12c)E5')
  security_warning(0);
else if (version == '12.1(12c)E4')
  security_warning(0);
else if (version == '12.1(12c)E3')
  security_warning(0);
else if (version == '12.1(12c)E2')
  security_warning(0);
else if (version == '12.1(12c)E1')
  security_warning(0);
else if (version == '12.1(12c)E')
  security_warning(0);
else if (version == '12.1(11b)E7')
  security_warning(0);
else if (version == '12.1(11b)E5')
  security_warning(0);
else if (version == '12.1(11b)E4')
  security_warning(0);
else if (version == '12.1(11b)E3')
  security_warning(0);
else if (version == '12.1(11b)E2')
  security_warning(0);
else if (version == '12.1(11b)E14')
  security_warning(0);
else if (version == '12.1(11b)E12')
  security_warning(0);
else if (version == '12.1(11b)E11')
  security_warning(0);
else if (version == '12.1(11b)E10')
  security_warning(0);
else if (version == '12.1(11b)E1')
  security_warning(0);
else if (version == '12.1(11b)E0a')
  security_warning(0);
else if (version == '12.1(11b)E')
  security_warning(0);
else if (version == '12.1(10)E8')
  security_warning(0);
else if (version == '12.1(10)E7')
  security_warning(0);
else if (version == '12.1(10)E6a')
  security_warning(0);
else if (version == '12.1(10)E6')
  security_warning(0);
else if (version == '12.1(10)E5')
  security_warning(0);
else if (version == '12.1(10)E4')
  security_warning(0);
else if (version == '12.1(10)E3')
  security_warning(0);
else if (version == '12.1(10)E2')
  security_warning(0);
else if (version == '12.1(10)E1')
  security_warning(0);
else if (version == '12.1(10)E')
  security_warning(0);
else if (version == '12.1(9)E3')
  security_warning(0);
else if (version == '12.1(9)E2')
  security_warning(0);
else if (version == '12.1(9)E1')
  security_warning(0);
else if (version == '12.1(9)E')
  security_warning(0);
else if (version == '12.1(8b)E9')
  security_warning(0);
else if (version == '12.1(8b)E8')
  security_warning(0);
else if (version == '12.1(8b)E7')
  security_warning(0);
else if (version == '12.1(8b)E6')
  security_warning(0);
else if (version == '12.1(8b)E20')
  security_warning(0);
else if (version == '12.1(8b)E19')
  security_warning(0);
else if (version == '12.1(8b)E18')
  security_warning(0);
else if (version == '12.1(8b)E15')
  security_warning(0);
else if (version == '12.1(8b)E14')
  security_warning(0);
else if (version == '12.1(8b)E13')
  security_warning(0);
else if (version == '12.1(8b)E12')
  security_warning(0);
else if (version == '12.1(8b)E11')
  security_warning(0);
else if (version == '12.1(8b)E10')
  security_warning(0);
else if (version == '12.1(8a)E5')
  security_warning(0);
else if (version == '12.1(8a)E4')
  security_warning(0);
else if (version == '12.1(8a)E3')
  security_warning(0);
else if (version == '12.1(8a)E2')
  security_warning(0);
else if (version == '12.1(8a)E1')
  security_warning(0);
else if (version == '12.1(8a)E')
  security_warning(0);
else if (version == '12.1(7a)E6')
  security_warning(0);
else if (version == '12.1(7a)E5')
  security_warning(0);
else if (version == '12.1(7a)E4')
  security_warning(0);
else if (version == '12.1(7a)E3')
  security_warning(0);
else if (version == '12.1(7a)E2')
  security_warning(0);
else if (version == '12.1(7a)E1a')
  security_warning(0);
else if (version == '12.1(7a)E1')
  security_warning(0);
else if (version == '12.1(7)E0a')
  security_warning(0);
else if (version == '12.1(7)E')
  security_warning(0);
else if (version == '12.1(6)E8')
  security_warning(0);
else if (version == '12.1(6)E6')
  security_warning(0);
else if (version == '12.1(6)E5')
  security_warning(0);
else if (version == '12.1(6)E4')
  security_warning(0);
else if (version == '12.1(6)E3')
  security_warning(0);
else if (version == '12.1(6)E2')
  security_warning(0);
else if (version == '12.1(6)E13')
  security_warning(0);
else if (version == '12.1(6)E1')
  security_warning(0);
else if (version == '12.1(6)E')
  security_warning(0);
else if (version == '12.1(5c)E9')
  security_warning(0);
else if (version == '12.1(5c)E8')
  security_warning(0);
else if (version == '12.1(5c)E12')
  security_warning(0);
else if (version == '12.1(5c)E10')
  security_warning(0);
else if (version == '12.1(5b)E7')
  security_warning(0);
else if (version == '12.1(5a)E4')
  security_warning(0);
else if (version == '12.1(5a)E3')
  security_warning(0);
else if (version == '12.1(5a)E2')
  security_warning(0);
else if (version == '12.1(5a)E1')
  security_warning(0);
else if (version == '12.1(5a)E')
  security_warning(0);
else if (version == '12.1(4)E3')
  security_warning(0);
else if (version == '12.1(4)E2')
  security_warning(0);
else if (version == '12.1(4)E1')
  security_warning(0);
else if (version == '12.1(4)E')
  security_warning(0);
else if (version == '12.1(3a)E8')
  security_warning(0);
else if (version == '12.1(3a)E7')
  security_warning(0);
else if (version == '12.1(3a)E6')
  security_warning(0);
else if (version == '12.1(3a)E5')
  security_warning(0);
else if (version == '12.1(3a)E4')
  security_warning(0);
else if (version == '12.1(3a)E3')
  security_warning(0);
else if (version == '12.1(3a)E1')
  security_warning(0);
else if (version == '12.1(3a)E')
  security_warning(0);
else if (version == '12.1(2)E2')
  security_warning(0);
else if (version == '12.1(2)E1')
  security_warning(0);
else if (version == '12.1(2)E')
  security_warning(0);
else if (version == '12.1(1)E6')
  security_warning(0);
else if (version == '12.1(1)E5')
  security_warning(0);
else if (version == '12.1(1)E4')
  security_warning(0);
else if (version == '12.1(1)E3')
  security_warning(0);
else if (version == '12.1(1)E2')
  security_warning(0);
else if (version == '12.1(1)E1')
  security_warning(0);
else if (version == '12.1(1)E')
  security_warning(0);
else if (version == '12.1(5)DC3')
  security_warning(0);
else if (version == '12.1(5)DC2')
  security_warning(0);
else if (version == '12.1(5)DC1')
  security_warning(0);
else if (version == '12.1(5)DC')
  security_warning(0);
else if (version == '12.1(4)DC3')
  security_warning(0);
else if (version == '12.1(4)DC2')
  security_warning(0);
else if (version == '12.1(3)DC2')
  security_warning(0);
else if (version == '12.1(3)DC1')
  security_warning(0);
else if (version == '12.1(3)DC')
  security_warning(0);
else if (version == '12.1(1)DC2')
  security_warning(0);
else if (version == '12.1(1)DC1')
  security_warning(0);
else if (version == '12.1(1)DC')
  security_warning(0);
else if (version == '12.1(5)DB2')
  security_warning(0);
else if (version == '12.1(5)DB1')
  security_warning(0);
else if (version == '12.1(5)DB')
  security_warning(0);
else if (version == '12.1(4)DB2')
  security_warning(0);
else if (version == '12.1(4)DB1')
  security_warning(0);
else if (version == '12.1(3)DB1')
  security_warning(0);
else if (version == '12.1(3)DB')
  security_warning(0);
else if (version == '12.1(1)DB2')
  security_warning(0);
else if (version == '12.1(1)DB')
  security_warning(0);
else if (version == '12.1(7)DA3')
  security_warning(0);
else if (version == '12.1(7)DA2')
  security_warning(0);
else if (version == '12.1(7)DA1')
  security_warning(0);
else if (version == '12.1(7)DA')
  security_warning(0);
else if (version == '12.1(6)DA1')
  security_warning(0);
else if (version == '12.1(6)DA')
  security_warning(0);
else if (version == '12.1(5)DA1')
  security_warning(0);
else if (version == '12.1(5)DA')
  security_warning(0);
else if (version == '12.1(4)DA')
  security_warning(0);
else if (version == '12.1(3)DA')
  security_warning(0);
else if (version == '12.1(2)DA')
  security_warning(0);
else if (version == '12.1(1)DA1')
  security_warning(0);
else if (version == '12.1(1)DA')
  security_warning(0);
else if (version == '12.1(7)CX1')
  security_warning(0);
else if (version == '12.1(7)CX')
  security_warning(0);
else if (version == '12.1(4)CX')
  security_warning(0);
else if (version == '12.1(14)AZ')
  security_warning(0);
else if (version == '12.1(13)AY')
  security_warning(0);
else if (version == '12.1(14)AX2')
  security_warning(0);
else if (version == '12.1(14)AX1')
  security_warning(0);
else if (version == '12.1(14)AX')
  security_warning(0);
else if (version == '12.1(11)AX')
  security_warning(0);
else if (version == '12.1(10)AA')
  security_warning(0);
else if (version == '12.1(8)AA1')
  security_warning(0);
else if (version == '12.1(8)AA')
  security_warning(0);
else if (version == '12.1(7)AA')
  security_warning(0);
else if (version == '12.1(6)AA')
  security_warning(0);
else if (version == '12.1(5)AA')
  security_warning(0);
else if (version == '12.1(4)AA')
  security_warning(0);
else if (version == '12.1(3)AA')
  security_warning(0);
else if (version == '12.1(2a)AA')
  security_warning(0);
else if (version == '12.1(1)AA1')
  security_warning(0);
else if (version == '12.1(1)AA')
  security_warning(0);
else if (version == '12.1(25)')
  security_warning(0);
else if (version == '12.1(24)')
  security_warning(0);
else if (version == '12.1(22c)')
  security_warning(0);
else if (version == '12.1(22b)')
  security_warning(0);
else if (version == '12.1(22a)')
  security_warning(0);
else if (version == '12.1(22)')
  security_warning(0);
else if (version == '12.1(21)')
  security_warning(0);
else if (version == '12.1(20a)')
  security_warning(0);
else if (version == '12.1(20)')
  security_warning(0);
else if (version == '12.1(19)')
  security_warning(0);
else if (version == '12.1(18)')
  security_warning(0);
else if (version == '12.1(17a)')
  security_warning(0);
else if (version == '12.1(17)')
  security_warning(0);
else if (version == '12.1(16)')
  security_warning(0);
else if (version == '12.1(15)')
  security_warning(0);
else if (version == '12.1(14)')
  security_warning(0);
else if (version == '12.1(13a)')
  security_warning(0);
else if (version == '12.1(13)')
  security_warning(0);
else if (version == '12.1(12c)')
  security_warning(0);
else if (version == '12.1(12b)')
  security_warning(0);
else if (version == '12.1(12a)')
  security_warning(0);
else if (version == '12.1(12)')
  security_warning(0);
else if (version == '12.1(11b)')
  security_warning(0);
else if (version == '12.1(11a)')
  security_warning(0);
else if (version == '12.1(11)')
  security_warning(0);
else if (version == '12.1(10a)')
  security_warning(0);
else if (version == '12.1(10)')
  security_warning(0);
else if (version == '12.1(9a)')
  security_warning(0);
else if (version == '12.1(9)')
  security_warning(0);
else if (version == '12.1(8b)')
  security_warning(0);
else if (version == '12.1(8a)')
  security_warning(0);
else if (version == '12.1(8)')
  security_warning(0);
else if (version == '12.1(7c)')
  security_warning(0);
else if (version == '12.1(7b)')
  security_warning(0);
else if (version == '12.1(7a)')
  security_warning(0);
else if (version == '12.1(7)')
  security_warning(0);
else if (version == '12.1(6b)')
  security_warning(0);
else if (version == '12.1(6a)')
  security_warning(0);
else if (version == '12.1(6)')
  security_warning(0);
else if (version == '12.1(5e)')
  security_warning(0);
else if (version == '12.1(5d)')
  security_warning(0);
else if (version == '12.1(5c)')
  security_warning(0);
else if (version == '12.1(5b)')
  security_warning(0);
else if (version == '12.1(5a)')
  security_warning(0);
else if (version == '12.1(5)')
  security_warning(0);
else if (version == '12.1(4c)')
  security_warning(0);
else if (version == '12.1(4b)')
  security_warning(0);
else if (version == '12.1(4a)')
  security_warning(0);
else if (version == '12.1(3b)')
  security_warning(0);
else if (version == '12.1(3)')
  security_warning(0);
else if (version == '12.1(2b)')
  security_warning(0);
else if (version == '12.1(2a)')
  security_warning(0);
else if (version == '12.1(2)')
  security_warning(0);
else if (version == '12.1(1c)')
  security_warning(0);
else if (version == '12.1(1b)')
  security_warning(0);
else if (version == '12.1(1a)')
  security_warning(0);
else if (version == '12.1(1)')
  security_warning(0);
else if (version == '12.0(7)XV')
  security_warning(0);
else if (version == '12.0(5)XT1')
  security_warning(0);
else if (version == '12.0(5)XS2')
  security_warning(0);
else if (version == '12.0(5)XS1')
  security_warning(0);
else if (version == '12.0(5)XS')
  security_warning(0);
else if (version == '12.0(7)XR4')
  security_warning(0);
else if (version == '12.0(7)XR3')
  security_warning(0);
else if (version == '12.0(7)XR2')
  security_warning(0);
else if (version == '12.0(7)XR1')
  security_warning(0);
else if (version == '12.0(5)XQ1')
  security_warning(0);
else if (version == '12.0(5)XQ')
  security_warning(0);
else if (version == '12.0(5)XN')
  security_warning(0);
else if (version == '12.0(4)XM1')
  security_warning(0);
else if (version == '12.0(4)XM')
  security_warning(0);
else if (version == '12.0(4)XL1')
  security_warning(0);
else if (version == '12.0(4)XL')
  security_warning(0);
else if (version == '12.0(7)XK3')
  security_warning(0);
else if (version == '12.0(7)XK2')
  security_warning(0);
else if (version == '12.0(7)XK1')
  security_warning(0);
else if (version == '12.0(7)XK')
  security_warning(0);
else if (version == '12.0(5)XK2')
  security_warning(0);
else if (version == '12.0(5)XK1')
  security_warning(0);
else if (version == '12.0(5)XK')
  security_warning(0);
else if (version == '12.0(4)XJ6')
  security_warning(0);
else if (version == '12.0(4)XJ5')
  security_warning(0);
else if (version == '12.0(4)XJ4')
  security_warning(0);
else if (version == '12.0(4)XJ3')
  security_warning(0);
else if (version == '12.0(4)XJ2')
  security_warning(0);
else if (version == '12.0(4)XJ1')
  security_warning(0);
else if (version == '12.0(4)XJ')
  security_warning(0);
else if (version == '12.0(4)XI2')
  security_warning(0);
else if (version == '12.0(4)XI1')
  security_warning(0);
else if (version == '12.0(4)XI')
  security_warning(0);
else if (version == '12.0(4)XH4')
  security_warning(0);
else if (version == '12.0(4)XH3')
  security_warning(0);
else if (version == '12.0(4)XH1')
  security_warning(0);
else if (version == '12.0(4)XH')
  security_warning(0);
else if (version == '12.0(2)XH')
  security_warning(0);
else if (version == '12.0(3)XG')
  security_warning(0);
else if (version == '12.0(7)XE2')
  security_warning(0);
else if (version == '12.0(7)XE1')
  security_warning(0);
else if (version == '12.0(5)XE8')
  security_warning(0);
else if (version == '12.0(5)XE7')
  security_warning(0);
else if (version == '12.0(5)XE6')
  security_warning(0);
else if (version == '12.0(5)XE5')
  security_warning(0);
else if (version == '12.0(5)XE4')
  security_warning(0);
else if (version == '12.0(5)XE3')
  security_warning(0);
else if (version == '12.0(5)XE2')
  security_warning(0);
else if (version == '12.0(5)XE1')
  security_warning(0);
else if (version == '12.0(5)XE')
  security_warning(0);
else if (version == '12.0(4)XE2')
  security_warning(0);
else if (version == '12.0(4)XE1')
  security_warning(0);
else if (version == '12.0(4)XE')
  security_warning(0);
else if (version == '12.0(3)XE2')
  security_warning(0);
else if (version == '12.0(3)XE1')
  security_warning(0);
else if (version == '12.0(3)XE')
  security_warning(0);
else if (version == '12.0(2)XE4')
  security_warning(0);
else if (version == '12.0(2)XE3')
  security_warning(0);
else if (version == '12.0(2)XE2')
  security_warning(0);
else if (version == '12.0(2)XE1')
  security_warning(0);
else if (version == '12.0(2)XE')
  security_warning(0);
else if (version == '12.0(1)XE')
  security_warning(0);
else if (version == '12.0(2)XD1')
  security_warning(0);
else if (version == '12.0(2)XC2')
  security_warning(0);
else if (version == '12.0(2)XC1')
  security_warning(0);
else if (version == '12.0(2)XC')
  security_warning(0);
else if (version == '12.0(1)XB1')
  security_warning(0);
else if (version == '12.0(1)XB')
  security_warning(0);
else if (version == '12.0(1)XA3')
  security_warning(0);
else if (version == '12.0(1)XA2')
  security_warning(0);
else if (version == '12.0(1)XA')
  security_warning(0);
else if (version == '12.0(5)WC9a')
  security_warning(0);
else if (version == '12.0(5)WC9')
  security_warning(0);
else if (version == '12.0(5)WC8')
  security_warning(0);
else if (version == '12.0(5)WC7')
  security_warning(0);
else if (version == '12.0(5)WC6')
  security_warning(0);
else if (version == '12.0(5)WC5a')
  security_warning(0);
else if (version == '12.0(5)WC5')
  security_warning(0);
else if (version == '12.0(5)WC4a')
  security_warning(0);
else if (version == '12.0(5)WC4')
  security_warning(0);
else if (version == '12.0(5)WC3a')
  security_warning(0);
else if (version == '12.0(5)WC10')
  security_warning(0);
else if (version == '12.0(7)T3')
  security_warning(0);
else if (version == '12.0(7)T2')
  security_warning(0);
else if (version == '12.0(7)T')
  security_warning(0);
else if (version == '12.0(5)T2')
  security_warning(0);
else if (version == '12.0(5)T1')
  security_warning(0);
else if (version == '12.0(5)T')
  security_warning(0);
else if (version == '12.0(4)T1')
  security_warning(0);
else if (version == '12.0(4)T')
  security_warning(0);
else if (version == '12.0(3)T3')
  security_warning(0);
else if (version == '12.0(3)T2')
  security_warning(0);
else if (version == '12.0(3)T1')
  security_warning(0);
else if (version == '12.0(3)T')
  security_warning(0);
else if (version == '12.0(2a)T1')
  security_warning(0);
else if (version == '12.0(2)T1')
  security_warning(0);
else if (version == '12.0(2)T')
  security_warning(0);
else if (version == '12.0(1)T')
  security_warning(0);
else if (version == '12.0(23)SZ3')
  security_warning(0);
else if (version == '12.0(21)SZ')
  security_warning(0);
else if (version == '12.0(25)SX9')
  security_warning(0);
else if (version == '12.0(25)SX8')
  security_warning(0);
else if (version == '12.0(25)SX7')
  security_warning(0);
else if (version == '12.0(25)SX6e')
  security_warning(0);
else if (version == '12.0(25)SX6')
  security_warning(0);
else if (version == '12.0(25)SX5')
  security_warning(0);
else if (version == '12.0(25)SX4')
  security_warning(0);
else if (version == '12.0(25)SX3')
  security_warning(0);
else if (version == '12.0(25)SX2')
  security_warning(0);
else if (version == '12.0(25)SX10')
  security_warning(0);
else if (version == '12.0(25)SX1')
  security_warning(0);
else if (version == '12.0(25)SX')
  security_warning(0);
else if (version == '12.0(23)SX5')
  security_warning(0);
else if (version == '12.0(23)SX4')
  security_warning(0);
else if (version == '12.0(23)SX3')
  security_warning(0);
else if (version == '12.0(23)SX2')
  security_warning(0);
else if (version == '12.0(23)SX1')
  security_warning(0);
else if (version == '12.0(23)SX')
  security_warning(0);
else if (version == '12.0(21)SX1')
  security_warning(0);
else if (version == '12.0(21)SX')
  security_warning(0);
else if (version == '12.0(10)SX')
  security_warning(0);
else if (version == '12.0(28)SW1')
  security_warning(0);
else if (version == '12.0(21)ST7')
  security_warning(0);
else if (version == '12.0(21)ST6a')
  security_warning(0);
else if (version == '12.0(21)ST6')
  security_warning(0);
else if (version == '12.0(21)ST5')
  security_warning(0);
else if (version == '12.0(21)ST4')
  security_warning(0);
else if (version == '12.0(21)ST3a')
  security_warning(0);
else if (version == '12.0(21)ST3')
  security_warning(0);
else if (version == '12.0(21)ST2b')
  security_warning(0);
else if (version == '12.0(21)ST2a')
  security_warning(0);
else if (version == '12.0(21)ST2')
  security_warning(0);
else if (version == '12.0(21)ST1')
  security_warning(0);
else if (version == '12.0(21)ST')
  security_warning(0);
else if (version == '12.0(20)ST6')
  security_warning(0);
else if (version == '12.0(20)ST5')
  security_warning(0);
else if (version == '12.0(20)ST4')
  security_warning(0);
else if (version == '12.0(20)ST3')
  security_warning(0);
else if (version == '12.0(20)ST2')
  security_warning(0);
else if (version == '12.0(20)ST1')
  security_warning(0);
else if (version == '12.0(20)ST')
  security_warning(0);
else if (version == '12.0(19)ST6')
  security_warning(0);
else if (version == '12.0(19)ST5')
  security_warning(0);
else if (version == '12.0(19)ST4')
  security_warning(0);
else if (version == '12.0(19)ST3')
  security_warning(0);
else if (version == '12.0(19)ST2')
  security_warning(0);
else if (version == '12.0(19)ST1')
  security_warning(0);
else if (version == '12.0(19)ST')
  security_warning(0);
else if (version == '12.0(18)ST1')
  security_warning(0);
else if (version == '12.0(18)ST')
  security_warning(0);
else if (version == '12.0(17)ST8')
  security_warning(0);
else if (version == '12.0(17)ST7')
  security_warning(0);
else if (version == '12.0(17)ST6')
  security_warning(0);
else if (version == '12.0(17)ST5')
  security_warning(0);
else if (version == '12.0(17)ST4')
  security_warning(0);
else if (version == '12.0(17)ST3')
  security_warning(0);
else if (version == '12.0(17)ST2')
  security_warning(0);
else if (version == '12.0(17)ST1')
  security_warning(0);
else if (version == '12.0(17)ST')
  security_warning(0);
else if (version == '12.0(16)ST1')
  security_warning(0);
else if (version == '12.0(16)ST')
  security_warning(0);
else if (version == '12.0(14)ST3')
  security_warning(0);
else if (version == '12.0(14)ST2')
  security_warning(0);
else if (version == '12.0(14)ST1')
  security_warning(0);
else if (version == '12.0(14)ST')
  security_warning(0);
else if (version == '12.0(11)ST4')
  security_warning(0);
else if (version == '12.0(11)ST3')
  security_warning(0);
else if (version == '12.0(11)ST2')
  security_warning(0);
else if (version == '12.0(11)ST1')
  security_warning(0);
else if (version == '12.0(11)ST')
  security_warning(0);
else if (version == '12.0(10)ST2')
  security_warning(0);
else if (version == '12.0(10)ST1')
  security_warning(0);
else if (version == '12.0(10)ST')
  security_warning(0);
else if (version == '12.0(9)ST')
  security_warning(0);
else if (version == '12.0(21)SP4')
  security_warning(0);
else if (version == '12.0(21)SP3')
  security_warning(0);
else if (version == '12.0(21)SP2')
  security_warning(0);
else if (version == '12.0(21)SP1')
  security_warning(0);
else if (version == '12.0(21)SP')
  security_warning(0);
else if (version == '12.0(20)SP2')
  security_warning(0);
else if (version == '12.0(20)SP1')
  security_warning(0);
else if (version == '12.0(20)SP')
  security_warning(0);
else if (version == '12.0(19)SP')
  security_warning(0);
else if (version == '12.0(19)SL4')
  security_warning(0);
else if (version == '12.0(19)SL3')
  security_warning(0);
else if (version == '12.0(19)SL2')
  security_warning(0);
else if (version == '12.0(19)SL1')
  security_warning(0);
else if (version == '12.0(19)SL')
  security_warning(0);
else if (version == '12.0(17)SL8')
  security_warning(0);
else if (version == '12.0(17)SL6')
  security_warning(0);
else if (version == '12.0(17)SL5')
  security_warning(0);
else if (version == '12.0(17)SL4')
  security_warning(0);
else if (version == '12.0(17)SL3')
  security_warning(0);
else if (version == '12.0(17)SL2')
  security_warning(0);
else if (version == '12.0(17)SL1')
  security_warning(0);
else if (version == '12.0(17)SL')
  security_warning(0);
else if (version == '12.0(15)SL')
  security_warning(0);
else if (version == '12.0(14)SL1')
  security_warning(0);
else if (version == '12.0(14)SL')
  security_warning(0);
else if (version == '12.0(11)SL1')
  security_warning(0);
else if (version == '12.0(11)SL')
  security_warning(0);
else if (version == '12.0(10)SL')
  security_warning(0);
else if (version == '12.0(9)SL2')
  security_warning(0);
else if (version == '12.0(9)SL1')
  security_warning(0);
else if (version == '12.0(9)SL')
  security_warning(0);
else if (version == '12.0(16)SC3')
  security_warning(0);
else if (version == '12.0(16)SC2')
  security_warning(0);
else if (version == '12.0(16)SC1')
  security_warning(0);
else if (version == '12.0(16)SC')
  security_warning(0);
else if (version == '12.0(15)SC1')
  security_warning(0);
else if (version == '12.0(15)SC')
  security_warning(0);
else if (version == '12.0(14)SC')
  security_warning(0);
else if (version == '12.0(13)SC')
  security_warning(0);
else if (version == '12.0(12)SC')
  security_warning(0);
else if (version == '12.0(11)SC')
  security_warning(0);
else if (version == '12.0(10)SC1')
  security_warning(0);
else if (version == '12.0(10)SC')
  security_warning(0);
else if (version == '12.0(9)SC')
  security_warning(0);
else if (version == '12.0(8)SC1')
  security_warning(0);
else if (version == '12.0(8)SC')
  security_warning(0);
else if (version == '12.0(7)SC')
  security_warning(0);
else if (version == '12.0(6)SC')
  security_warning(0);
else if (version == '12.0(29)S')
  security_warning(0);
else if (version == '12.0(28)S1')
  security_warning(0);
else if (version == '12.0(28)S')
  security_warning(0);
else if (version == '12.0(27)S3')
  security_warning(0);
else if (version == '12.0(27)S2a')
  security_warning(0);
else if (version == '12.0(27)S2')
  security_warning(0);
else if (version == '12.0(27)S1')
  security_warning(0);
else if (version == '12.0(27)S')
  security_warning(0);
else if (version == '12.0(26)S4')
  security_warning(0);
else if (version == '12.0(26)S3')
  security_warning(0);
else if (version == '12.0(26)S2c')
  security_warning(0);
else if (version == '12.0(26)S2')
  security_warning(0);
else if (version == '12.0(26)S1')
  security_warning(0);
else if (version == '12.0(26)S')
  security_warning(0);
else if (version == '12.0(25)S4')
  security_warning(0);
else if (version == '12.0(25)S3')
  security_warning(0);
else if (version == '12.0(25)S2')
  security_warning(0);
else if (version == '12.0(25)S1d')
  security_warning(0);
else if (version == '12.0(25)S1c')
  security_warning(0);
else if (version == '12.0(25)S1b')
  security_warning(0);
else if (version == '12.0(25)S1a')
  security_warning(0);
else if (version == '12.0(25)S1')
  security_warning(0);
else if (version == '12.0(25)S')
  security_warning(0);
else if (version == '12.0(24)S6')
  security_warning(0);
else if (version == '12.0(24)S5')
  security_warning(0);
else if (version == '12.0(24)S4a')
  security_warning(0);
else if (version == '12.0(24)S4')
  security_warning(0);
else if (version == '12.0(24)S3')
  security_warning(0);
else if (version == '12.0(24)S2b')
  security_warning(0);
else if (version == '12.0(24)S2a')
  security_warning(0);
else if (version == '12.0(24)S2')
  security_warning(0);
else if (version == '12.0(24)S1')
  security_warning(0);
else if (version == '12.0(24)S')
  security_warning(0);
else if (version == '12.0(23)S6a')
  security_warning(0);
else if (version == '12.0(23)S6')
  security_warning(0);
else if (version == '12.0(23)S5')
  security_warning(0);
else if (version == '12.0(23)S4')
  security_warning(0);
else if (version == '12.0(23)S3c')
  security_warning(0);
else if (version == '12.0(23)S3b')
  security_warning(0);
else if (version == '12.0(23)S3a')
  security_warning(0);
else if (version == '12.0(23)S3')
  security_warning(0);
else if (version == '12.0(23)S2a')
  security_warning(0);
else if (version == '12.0(23)S2')
  security_warning(0);
else if (version == '12.0(23)S1')
  security_warning(0);
else if (version == '12.0(23)S')
  security_warning(0);
else if (version == '12.0(22)S6')
  security_warning(0);
else if (version == '12.0(22)S5a')
  security_warning(0);
else if (version == '12.0(22)S5')
  security_warning(0);
else if (version == '12.0(22)S4a')
  security_warning(0);
else if (version == '12.0(22)S4')
  security_warning(0);
else if (version == '12.0(22)S3c')
  security_warning(0);
else if (version == '12.0(22)S3b')
  security_warning(0);
else if (version == '12.0(22)S3a')
  security_warning(0);
else if (version == '12.0(22)S3')
  security_warning(0);
else if (version == '12.0(22)S2e')
  security_warning(0);
else if (version == '12.0(22)S2d')
  security_warning(0);
else if (version == '12.0(22)S2c')
  security_warning(0);
else if (version == '12.0(22)S2b')
  security_warning(0);
else if (version == '12.0(22)S2a')
  security_warning(0);
else if (version == '12.0(22)S2')
  security_warning(0);
else if (version == '12.0(22)S1')
  security_warning(0);
else if (version == '12.0(22)S')
  security_warning(0);
else if (version == '12.0(21)S8')
  security_warning(0);
else if (version == '12.0(21)S7')
  security_warning(0);
else if (version == '12.0(21)S6a')
  security_warning(0);
else if (version == '12.0(21)S6')
  security_warning(0);
else if (version == '12.0(21)S5a')
  security_warning(0);
else if (version == '12.0(21)S5')
  security_warning(0);
else if (version == '12.0(21)S4a')
  security_warning(0);
else if (version == '12.0(21)S4')
  security_warning(0);
else if (version == '12.0(21)S3')
  security_warning(0);
else if (version == '12.0(21)S2')
  security_warning(0);
else if (version == '12.0(21)S1')
  security_warning(0);
else if (version == '12.0(21)S')
  security_warning(0);
else if (version == '12.0(19)S4')
  security_warning(0);
else if (version == '12.0(19)S3')
  security_warning(0);
else if (version == '12.0(19)S2a')
  security_warning(0);
else if (version == '12.0(19)S2')
  security_warning(0);
else if (version == '12.0(19)S1')
  security_warning(0);
else if (version == '12.0(19)S')
  security_warning(0);
else if (version == '12.0(18)S7')
  security_warning(0);
else if (version == '12.0(18)S6')
  security_warning(0);
else if (version == '12.0(18)S5a')
  security_warning(0);
else if (version == '12.0(18)S5')
  security_warning(0);
else if (version == '12.0(18)S4')
  security_warning(0);
else if (version == '12.0(18)S3')
  security_warning(0);
else if (version == '12.0(18)S2')
  security_warning(0);
else if (version == '12.0(18)S1')
  security_warning(0);
else if (version == '12.0(18)S')
  security_warning(0);
else if (version == '12.0(17)S7')
  security_warning(0);
else if (version == '12.0(17)S6')
  security_warning(0);
else if (version == '12.0(17)S5')
  security_warning(0);
else if (version == '12.0(17)S4')
  security_warning(0);
else if (version == '12.0(17)S3')
  security_warning(0);
else if (version == '12.0(17)S2')
  security_warning(0);
else if (version == '12.0(17)S1')
  security_warning(0);
else if (version == '12.0(17)S')
  security_warning(0);
else if (version == '12.0(16)S9')
  security_warning(0);
else if (version == '12.0(16)S8a')
  security_warning(0);
else if (version == '12.0(16)S8')
  security_warning(0);
else if (version == '12.0(16)S7')
  security_warning(0);
else if (version == '12.0(16)S6')
  security_warning(0);
else if (version == '12.0(16)S5')
  security_warning(0);
else if (version == '12.0(16)S4')
  security_warning(0);
else if (version == '12.0(16)S3')
  security_warning(0);
else if (version == '12.0(16)S2')
  security_warning(0);
else if (version == '12.0(16)S10')
  security_warning(0);
else if (version == '12.0(16)S1')
  security_warning(0);
else if (version == '12.0(16)S')
  security_warning(0);
else if (version == '12.0(15)S7')
  security_warning(0);
else if (version == '12.0(15)S6')
  security_warning(0);
else if (version == '12.0(15)S5')
  security_warning(0);
else if (version == '12.0(15)S4')
  security_warning(0);
else if (version == '12.0(15)S3')
  security_warning(0);
else if (version == '12.0(15)S2')
  security_warning(0);
else if (version == '12.0(15)S1')
  security_warning(0);
else if (version == '12.0(15)S')
  security_warning(0);
else if (version == '12.0(14)S8')
  security_warning(0);
else if (version == '12.0(14)S7')
  security_warning(0);
else if (version == '12.0(14)S6')
  security_warning(0);
else if (version == '12.0(14)S5')
  security_warning(0);
else if (version == '12.0(14)S4')
  security_warning(0);
else if (version == '12.0(14)S3')
  security_warning(0);
else if (version == '12.0(14)S2')
  security_warning(0);
else if (version == '12.0(14)S1')
  security_warning(0);
else if (version == '12.0(14)S')
  security_warning(0);
else if (version == '12.0(13)S8')
  security_warning(0);
else if (version == '12.0(13)S6')
  security_warning(0);
else if (version == '12.0(13)S5')
  security_warning(0);
else if (version == '12.0(13)S4')
  security_warning(0);
else if (version == '12.0(13)S3')
  security_warning(0);
else if (version == '12.0(13)S2')
  security_warning(0);
else if (version == '12.0(13)S1')
  security_warning(0);
else if (version == '12.0(13)S')
  security_warning(0);
else if (version == '12.0(12)S4')
  security_warning(0);
else if (version == '12.0(12)S3')
  security_warning(0);
else if (version == '12.0(12)S2')
  security_warning(0);
else if (version == '12.0(12)S1')
  security_warning(0);
else if (version == '12.0(12)S')
  security_warning(0);
else if (version == '12.0(11)S6')
  security_warning(0);
else if (version == '12.0(11)S5')
  security_warning(0);
else if (version == '12.0(11)S4')
  security_warning(0);
else if (version == '12.0(11)S3')
  security_warning(0);
else if (version == '12.0(11)S2')
  security_warning(0);
else if (version == '12.0(11)S1')
  security_warning(0);
else if (version == '12.0(11)S')
  security_warning(0);
else if (version == '12.0(10)S8')
  security_warning(0);
else if (version == '12.0(10)S7')
  security_warning(0);
else if (version == '12.0(10)S5')
  security_warning(0);
else if (version == '12.0(10)S4')
  security_warning(0);
else if (version == '12.0(10)S3b')
  security_warning(0);
else if (version == '12.0(10)S3')
  security_warning(0);
else if (version == '12.0(10)S2')
  security_warning(0);
else if (version == '12.0(10)S1')
  security_warning(0);
else if (version == '12.0(10)S')
  security_warning(0);
else if (version == '12.0(9)S8')
  security_warning(0);
else if (version == '12.0(9)S')
  security_warning(0);
else if (version == '12.0(8)S1')
  security_warning(0);
else if (version == '12.0(8)S')
  security_warning(0);
else if (version == '12.0(7)S1')
  security_warning(0);
else if (version == '12.0(7)S')
  security_warning(0);
else if (version == '12.0(6)S2')
  security_warning(0);
else if (version == '12.0(6)S1')
  security_warning(0);
else if (version == '12.0(6)S')
  security_warning(0);
else if (version == '12.0(5)S')
  security_warning(0);
else if (version == '12.0(4)S')
  security_warning(0);
else if (version == '12.0(3)S')
  security_warning(0);
else if (version == '12.0(2)S')
  security_warning(0);
else if (version == '12.0(7)DC1')
  security_warning(0);
else if (version == '12.0(7)DC')
  security_warning(0);
else if (version == '12.0(7)DB2')
  security_warning(0);
else if (version == '12.0(7)DB1')
  security_warning(0);
else if (version == '12.0(7)DB')
  security_warning(0);
else if (version == '12.0(3)DB')
  security_warning(0);
else if (version == '12.0(2)DB')
  security_warning(0);
else if (version == '12.0(8)DA')
  security_warning(0);
else if (version == '12.0(28a)')
  security_warning(0);
else if (version == '12.0(28)')
  security_warning(0);
else if (version == '12.0(27)')
  security_warning(0);
else if (version == '12.0(26)')
  security_warning(0);
else if (version == '12.0(25)')
  security_warning(0);
else if (version == '12.0(24)')
  security_warning(0);
else if (version == '12.0(23)')
  security_warning(0);
else if (version == '12.0(22)')
  security_warning(0);
else if (version == '12.0(21a)')
  security_warning(0);
else if (version == '12.0(21)')
  security_warning(0);
else if (version == '12.0(20a)')
  security_warning(0);
else if (version == '12.0(20)')
  security_warning(0);
else if (version == '12.0(19b)')
  security_warning(0);
else if (version == '12.0(19a)')
  security_warning(0);
else if (version == '12.0(19)')
  security_warning(0);
else if (version == '12.0(18b)')
  security_warning(0);
else if (version == '12.0(18a)')
  security_warning(0);
else if (version == '12.0(18)')
  security_warning(0);
else if (version == '12.0(17a)')
  security_warning(0);
else if (version == '12.0(17)')
  security_warning(0);
else if (version == '12.0(16a)')
  security_warning(0);
else if (version == '12.0(16)')
  security_warning(0);
else if (version == '12.0(15b)')
  security_warning(0);
else if (version == '12.0(15a)')
  security_warning(0);
else if (version == '12.0(15)')
  security_warning(0);
else if (version == '12.0(14a)')
  security_warning(0);
else if (version == '12.0(14)')
  security_warning(0);
else if (version == '12.0(13a)')
  security_warning(0);
else if (version == '12.0(13)')
  security_warning(0);
else if (version == '12.0(12a)')
  security_warning(0);
else if (version == '12.0(12)')
  security_warning(0);
else if (version == '12.0(11a)')
  security_warning(0);
else if (version == '12.0(11)')
  security_warning(0);
else if (version == '12.0(10a)')
  security_warning(0);
else if (version == '12.0(10)')
  security_warning(0);
else if (version == '12.0(9a)')
  security_warning(0);
else if (version == '12.0(9)')
  security_warning(0);
else if (version == '12.0(8a)')
  security_warning(0);
else if (version == '12.0(8)')
  security_warning(0);
else if (version == '12.0(7a)')
  security_warning(0);
else if (version == '12.0(7)')
  security_warning(0);
else if (version == '12.0(6b)')
  security_warning(0);
else if (version == '12.0(6a)')
  security_warning(0);
else if (version == '12.0(6)')
  security_warning(0);
else if (version == '12.0(5a)')
  security_warning(0);
else if (version == '12.0(5)')
  security_warning(0);
else if (version == '12.0(4b)')
  security_warning(0);
else if (version == '12.0(4a)')
  security_warning(0);
else if (version == '12.0(4)')
  security_warning(0);
else if (version == '12.0(3d)')
  security_warning(0);
else if (version == '12.0(3c)')
  security_warning(0);
else if (version == '12.0(3b)')
  security_warning(0);
else if (version == '12.0(3)')
  security_warning(0);
else if (version == '12.0(2b)')
  security_warning(0);
else if (version == '12.0(2a)')
  security_warning(0);
else if (version == '12.0(2)')
  security_warning(0);
else if (version == '12.0(1a)')
  security_warning(0);
else if (version == '12.0(1)')
  security_warning(0);
else
  exit(0, 'The host is not affected.');

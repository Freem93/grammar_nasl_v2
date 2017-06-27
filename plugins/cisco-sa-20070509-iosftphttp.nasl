#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00808399d0.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49003);
 script_version("$Revision: 1.12 $");
 script_cve_id("CVE-2007-2586", "CVE-2007-2587");
 script_bugtraq_id(23885);
 script_osvdb_id(35334, 35335);
 script_name(english:"Multiple Vulnerabilities in the IOS FTP Server");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'The Cisco IOS FTP Server feature contains multiple vulnerabilities that
can result in a denial of service (DoS) condition, improper
verification of user credentials, and the ability to retrieve or write
any file from the device filesystem, including the device\'s saved
configuration. This configuration file may include passwords or other
sensitive information.
The IOS FTP Server is an optional service that is disabled by default.
Devices that are not specifically configured to enable the IOS FTP
Server service are unaffected by these vulnerabilities.
These vulnerabilities do not apply to the IOS FTP Client feature.
');
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?97593100");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00808399d0.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?3f74164c");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070509-iosftp."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/09");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/05/09");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCek55259");
 script_xref(name:"CISCO-BUG-ID", value:"CSCse29244");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsg16908");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20070509-iosftp");
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

if (version == '12.4(6)XE2')
  security_hole(0);
else if (version == '12.4(6)XE1')
  security_hole(0);
else if (version == '12.4(6)XE')
  security_hole(0);
else if (version == '12.4(4)XD2')
  security_hole(0);
else if (version == '12.4(4)XD1')
  security_hole(0);
else if (version == '12.4(4)XD')
  security_hole(0);
else if (version == '12.4(4)XC5')
  security_hole(0);
else if (version == '12.4(4)XC4')
  security_hole(0);
else if (version == '12.4(4)XC3')
  security_hole(0);
else if (version == '12.4(4)XC2')
  security_hole(0);
else if (version == '12.4(4)XC1')
  security_hole(0);
else if (version == '12.4(4)XC')
  security_hole(0);
else if (version == '12.4(2)XA2')
  security_hole(0);
else if (version == '12.4(2)XA1')
  security_hole(0);
else if (version == '12.4(2)XA')
  security_hole(0);
else if (version == '12.4(9)T1')
  security_hole(0);
else if (version == '12.4(9)T')
  security_hole(0);
else if (version == '12.4(6)T5')
  security_hole(0);
else if (version == '12.4(6)T4')
  security_hole(0);
else if (version == '12.4(6)T3')
  security_hole(0);
else if (version == '12.4(6)T2')
  security_hole(0);
else if (version == '12.4(6)T1')
  security_hole(0);
else if (version == '12.4(6)T')
  security_hole(0);
else if (version == '12.4(4)T5')
  security_hole(0);
else if (version == '12.4(4)T4')
  security_hole(0);
else if (version == '12.4(4)T3')
  security_hole(0);
else if (version == '12.4(4)T2')
  security_hole(0);
else if (version == '12.4(4)T1')
  security_hole(0);
else if (version == '12.4(4)T')
  security_hole(0);
else if (version == '12.4(2)T5')
  security_hole(0);
else if (version == '12.4(2)T4')
  security_hole(0);
else if (version == '12.4(2)T3')
  security_hole(0);
else if (version == '12.4(2)T2')
  security_hole(0);
else if (version == '12.4(2)T1')
  security_hole(0);
else if (version == '12.4(2)T')
  security_hole(0);
else if (version == '12.4(11)SW1')
  security_hole(0);
else if (version == '12.4(11)SW')
  security_hole(0);
else if (version == '12.4(10a)')
  security_hole(0);
else if (version == '12.4(10)')
  security_hole(0);
else if (version == '12.4(8b)')
  security_hole(0);
else if (version == '12.4(8a)')
  security_hole(0);
else if (version == '12.4(8)')
  security_hole(0);
else if (version == '12.4(7c)')
  security_hole(0);
else if (version == '12.4(7b)')
  security_hole(0);
else if (version == '12.4(7a)')
  security_hole(0);
else if (version == '12.4(7)')
  security_hole(0);
else if (version == '12.4(5b)')
  security_hole(0);
else if (version == '12.4(5a)')
  security_hole(0);
else if (version == '12.4(5)')
  security_hole(0);
else if (version == '12.4(3f)')
  security_hole(0);
else if (version == '12.4(3e)')
  security_hole(0);
else if (version == '12.4(3d)')
  security_hole(0);
else if (version == '12.4(3c)')
  security_hole(0);
else if (version == '12.4(3b)')
  security_hole(0);
else if (version == '12.4(3a)')
  security_hole(0);
else if (version == '12.4(3)')
  security_hole(0);
else if (version == '12.4(1c)')
  security_hole(0);
else if (version == '12.4(1b)')
  security_hole(0);
else if (version == '12.4(1a)')
  security_hole(0);
else if (version == '12.4(1)')
  security_hole(0);
else if (version == '12.3(8)ZA')
  security_hole(0);
else if (version == '12.3(11)YZ1')
  security_hole(0);
else if (version == '12.3(11)YZ')
  security_hole(0);
else if (version == '12.3(14)YT1')
  security_hole(0);
else if (version == '12.3(14)YT')
  security_hole(0);
else if (version == '12.3(11)YS1')
  security_hole(0);
else if (version == '12.3(11)YS')
  security_hole(0);
else if (version == '12.3(14)YM9')
  security_hole(0);
else if (version == '12.3(14)YM8')
  security_hole(0);
else if (version == '12.3(14)YM7')
  security_hole(0);
else if (version == '12.3(14)YM6')
  security_hole(0);
else if (version == '12.3(14)YM5')
  security_hole(0);
else if (version == '12.3(14)YM4')
  security_hole(0);
else if (version == '12.3(14)YM3')
  security_hole(0);
else if (version == '12.3(14)YM2')
  security_hole(0);
else if (version == '12.3(11)YK2')
  security_hole(0);
else if (version == '12.3(11)YK1')
  security_hole(0);
else if (version == '12.3(11)YK')
  security_hole(0);
else if (version == '12.3(8)YI3')
  security_hole(0);
else if (version == '12.3(8)YI2')
  security_hole(0);
else if (version == '12.3(8)YI1')
  security_hole(0);
else if (version == '12.3(8)YH')
  security_hole(0);
else if (version == '12.3(8)YG5')
  security_hole(0);
else if (version == '12.3(8)YG4')
  security_hole(0);
else if (version == '12.3(8)YG3')
  security_hole(0);
else if (version == '12.3(8)YG2')
  security_hole(0);
else if (version == '12.3(8)YG1')
  security_hole(0);
else if (version == '12.3(8)YG')
  security_hole(0);
else if (version == '12.3(8)YD1')
  security_hole(0);
else if (version == '12.3(8)YD')
  security_hole(0);
else if (version == '12.3(8)YA1')
  security_hole(0);
else if (version == '12.3(8)YA')
  security_hole(0);
else if (version == '12.3(8)XX1')
  security_hole(0);
else if (version == '12.3(8)XX')
  security_hole(0);
else if (version == '12.3(7)XS2')
  security_hole(0);
else if (version == '12.3(7)XS1')
  security_hole(0);
else if (version == '12.3(7)XS')
  security_hole(0);
else if (version == '12.3(7)XR6')
  security_hole(0);
else if (version == '12.3(7)XR5')
  security_hole(0);
else if (version == '12.3(7)XR4')
  security_hole(0);
else if (version == '12.3(7)XR3')
  security_hole(0);
else if (version == '12.3(7)XR2')
  security_hole(0);
else if (version == '12.3(7)XR')
  security_hole(0);
else if (version == '12.3(4)XQ1')
  security_hole(0);
else if (version == '12.3(4)XQ')
  security_hole(0);
else if (version == '12.3(11)XL1')
  security_hole(0);
else if (version == '12.3(11)XL')
  security_hole(0);
else if (version == '12.3(4)XK4')
  security_hole(0);
else if (version == '12.3(4)XK3')
  security_hole(0);
else if (version == '12.3(4)XK2')
  security_hole(0);
else if (version == '12.3(4)XK1')
  security_hole(0);
else if (version == '12.3(4)XK')
  security_hole(0);
else if (version == '12.3(4)XG5')
  security_hole(0);
else if (version == '12.3(4)XG4')
  security_hole(0);
else if (version == '12.3(4)XG3')
  security_hole(0);
else if (version == '12.3(4)XG2')
  security_hole(0);
else if (version == '12.3(4)XG1')
  security_hole(0);
else if (version == '12.3(4)XG')
  security_hole(0);
else if (version == '12.3(2)XF')
  security_hole(0);
else if (version == '12.3(2)XE4')
  security_hole(0);
else if (version == '12.3(2)XE3')
  security_hole(0);
else if (version == '12.3(2)XE2')
  security_hole(0);
else if (version == '12.3(2)XE1')
  security_hole(0);
else if (version == '12.3(2)XE')
  security_hole(0);
else if (version == '12.3(4)XD4')
  security_hole(0);
else if (version == '12.3(4)XD3')
  security_hole(0);
else if (version == '12.3(4)XD2')
  security_hole(0);
else if (version == '12.3(4)XD1')
  security_hole(0);
else if (version == '12.3(4)XD')
  security_hole(0);
else if (version == '12.3(2)XC3')
  security_hole(0);
else if (version == '12.3(2)XC2')
  security_hole(0);
else if (version == '12.3(2)XC1')
  security_hole(0);
else if (version == '12.3(2)XC')
  security_hole(0);
else if (version == '12.3(2)XA5')
  security_hole(0);
else if (version == '12.3(2)XA4')
  security_hole(0);
else if (version == '12.3(2)XA3')
  security_hole(0);
else if (version == '12.3(2)XA2')
  security_hole(0);
else if (version == '12.3(2)XA1')
  security_hole(0);
else if (version == '12.3(2)XA')
  security_hole(0);
else if (version == '12.3(4)TPC11a')
  security_hole(0);
else if (version == '12.3(14)T7')
  security_hole(0);
else if (version == '12.3(14)T6')
  security_hole(0);
else if (version == '12.3(14)T5')
  security_hole(0);
else if (version == '12.3(14)T3')
  security_hole(0);
else if (version == '12.3(14)T2')
  security_hole(0);
else if (version == '12.3(14)T1')
  security_hole(0);
else if (version == '12.3(14)T')
  security_hole(0);
else if (version == '12.3(11)T9')
  security_hole(0);
else if (version == '12.3(11)T8')
  security_hole(0);
else if (version == '12.3(11)T7')
  security_hole(0);
else if (version == '12.3(11)T6')
  security_hole(0);
else if (version == '12.3(11)T5')
  security_hole(0);
else if (version == '12.3(11)T4')
  security_hole(0);
else if (version == '12.3(11)T3')
  security_hole(0);
else if (version == '12.3(11)T2')
  security_hole(0);
else if (version == '12.3(11)T11')
  security_hole(0);
else if (version == '12.3(11)T10')
  security_hole(0);
else if (version == '12.3(11)T')
  security_hole(0);
else if (version == '12.3(8)T9')
  security_hole(0);
else if (version == '12.3(8)T8')
  security_hole(0);
else if (version == '12.3(8)T7')
  security_hole(0);
else if (version == '12.3(8)T6')
  security_hole(0);
else if (version == '12.3(8)T5')
  security_hole(0);
else if (version == '12.3(8)T4')
  security_hole(0);
else if (version == '12.3(8)T3')
  security_hole(0);
else if (version == '12.3(8)T11')
  security_hole(0);
else if (version == '12.3(8)T10')
  security_hole(0);
else if (version == '12.3(8)T1')
  security_hole(0);
else if (version == '12.3(8)T')
  security_hole(0);
else if (version == '12.3(7)T9')
  security_hole(0);
else if (version == '12.3(7)T8')
  security_hole(0);
else if (version == '12.3(7)T7')
  security_hole(0);
else if (version == '12.3(7)T6')
  security_hole(0);
else if (version == '12.3(7)T4')
  security_hole(0);
else if (version == '12.3(7)T3')
  security_hole(0);
else if (version == '12.3(7)T2')
  security_hole(0);
else if (version == '12.3(7)T12')
  security_hole(0);
else if (version == '12.3(7)T11')
  security_hole(0);
else if (version == '12.3(7)T10')
  security_hole(0);
else if (version == '12.3(7)T1')
  security_hole(0);
else if (version == '12.3(7)T')
  security_hole(0);
else if (version == '12.3(4)T9')
  security_hole(0);
else if (version == '12.3(4)T8')
  security_hole(0);
else if (version == '12.3(4)T7')
  security_hole(0);
else if (version == '12.3(4)T6')
  security_hole(0);
else if (version == '12.3(4)T4')
  security_hole(0);
else if (version == '12.3(4)T3')
  security_hole(0);
else if (version == '12.3(4)T2')
  security_hole(0);
else if (version == '12.3(4)T11')
  security_hole(0);
else if (version == '12.3(4)T10')
  security_hole(0);
else if (version == '12.3(4)T1')
  security_hole(0);
else if (version == '12.3(4)T')
  security_hole(0);
else if (version == '12.3(2)T9')
  security_hole(0);
else if (version == '12.3(2)T8')
  security_hole(0);
else if (version == '12.3(2)T7')
  security_hole(0);
else if (version == '12.3(2)T6')
  security_hole(0);
else if (version == '12.3(2)T5')
  security_hole(0);
else if (version == '12.3(2)T4')
  security_hole(0);
else if (version == '12.3(2)T3')
  security_hole(0);
else if (version == '12.3(2)T2')
  security_hole(0);
else if (version == '12.3(2)T1')
  security_hole(0);
else if (version == '12.3(2)T')
  security_hole(0);
else if (version == '12.3(5a)B5')
  security_hole(0);
else if (version == '12.3(5a)B4')
  security_hole(0);
else if (version == '12.3(5a)B3')
  security_hole(0);
else if (version == '12.3(5a)B2')
  security_hole(0);
else if (version == '12.3(5a)B1')
  security_hole(0);
else if (version == '12.3(5a)B')
  security_hole(0);
else if (version == '12.3(3)B1')
  security_hole(0);
else if (version == '12.3(3)B')
  security_hole(0);
else if (version == '12.3(1a)B')
  security_hole(0);
else if (version == '12.3(20)')
  security_hole(0);
else if (version == '12.3(19)')
  security_hole(0);
else if (version == '12.3(18)')
  security_hole(0);
else if (version == '12.3(17b)')
  security_hole(0);
else if (version == '12.3(17a)')
  security_hole(0);
else if (version == '12.3(17)')
  security_hole(0);
else if (version == '12.3(16a)')
  security_hole(0);
else if (version == '12.3(16)')
  security_hole(0);
else if (version == '12.3(15b)')
  security_hole(0);
else if (version == '12.3(15a)')
  security_hole(0);
else if (version == '12.3(15)')
  security_hole(0);
else if (version == '12.3(13b)')
  security_hole(0);
else if (version == '12.3(13a)')
  security_hole(0);
else if (version == '12.3(13)')
  security_hole(0);
else if (version == '12.3(12e)')
  security_hole(0);
else if (version == '12.3(12d)')
  security_hole(0);
else if (version == '12.3(12c)')
  security_hole(0);
else if (version == '12.3(12b)')
  security_hole(0);
else if (version == '12.3(12a)')
  security_hole(0);
else if (version == '12.3(12)')
  security_hole(0);
else if (version == '12.3(10f)')
  security_hole(0);
else if (version == '12.3(10e)')
  security_hole(0);
else if (version == '12.3(10d)')
  security_hole(0);
else if (version == '12.3(10c)')
  security_hole(0);
else if (version == '12.3(10b)')
  security_hole(0);
else if (version == '12.3(10a)')
  security_hole(0);
else if (version == '12.3(10)')
  security_hole(0);
else if (version == '12.3(9e)')
  security_hole(0);
else if (version == '12.3(9d)')
  security_hole(0);
else if (version == '12.3(9c)')
  security_hole(0);
else if (version == '12.3(9b)')
  security_hole(0);
else if (version == '12.3(9a)')
  security_hole(0);
else if (version == '12.3(9)')
  security_hole(0);
else if (version == '12.3(6f)')
  security_hole(0);
else if (version == '12.3(6e)')
  security_hole(0);
else if (version == '12.3(6c)')
  security_hole(0);
else if (version == '12.3(6b)')
  security_hole(0);
else if (version == '12.3(6a)')
  security_hole(0);
else if (version == '12.3(6)')
  security_hole(0);
else if (version == '12.3(5f)')
  security_hole(0);
else if (version == '12.3(5e)')
  security_hole(0);
else if (version == '12.3(5d)')
  security_hole(0);
else if (version == '12.3(5c)')
  security_hole(0);
else if (version == '12.3(5b)')
  security_hole(0);
else if (version == '12.3(5a)')
  security_hole(0);
else if (version == '12.3(5)')
  security_hole(0);
else if (version == '12.3(3i)')
  security_hole(0);
else if (version == '12.3(3h)')
  security_hole(0);
else if (version == '12.3(3g)')
  security_hole(0);
else if (version == '12.3(3f)')
  security_hole(0);
else if (version == '12.3(3e)')
  security_hole(0);
else if (version == '12.3(3c)')
  security_hole(0);
else if (version == '12.3(3b)')
  security_hole(0);
else if (version == '12.3(3a)')
  security_hole(0);
else if (version == '12.3(3)')
  security_hole(0);
else if (version == '12.3(1a)')
  security_hole(0);
else if (version == '12.3(1)')
  security_hole(0);
else if (version == '12.2(15)ZL1')
  security_hole(0);
else if (version == '12.2(15)ZL')
  security_hole(0);
else if (version == '12.2(15)ZJ5')
  security_hole(0);
else if (version == '12.2(15)ZJ3')
  security_hole(0);
else if (version == '12.2(15)ZJ2')
  security_hole(0);
else if (version == '12.2(15)ZJ1')
  security_hole(0);
else if (version == '12.2(15)ZJ')
  security_hole(0);
else if (version == '12.2(13)ZH5')
  security_hole(0);
else if (version == '12.2(13)ZH4')
  security_hole(0);
else if (version == '12.2(13)ZH3')
  security_hole(0);
else if (version == '12.2(13)ZH2')
  security_hole(0);
else if (version == '12.2(13)ZH1')
  security_hole(0);
else if (version == '12.2(13)ZH')
  security_hole(0);
else if (version == '12.2(13)ZF2')
  security_hole(0);
else if (version == '12.2(13)ZF1')
  security_hole(0);
else if (version == '12.2(13)ZF')
  security_hole(0);
else if (version == '12.2(2)XT3')
  security_hole(0);
else if (version == '12.2(2)XT2')
  security_hole(0);
else if (version == '12.2(2)XT')
  security_hole(0);
else if (version == '12.2(2)XG1')
  security_hole(0);
else if (version == '12.2(2)XG')
  security_hole(0);
else if (version == '12.2(2)XA5')
  security_hole(0);
else if (version == '12.2(2)XA4')
  security_hole(0);
else if (version == '12.2(2)XA1')
  security_hole(0);
else if (version == '12.2(2)XA')
  security_hole(0);
else if (version == '12.2(15)T9')
  security_hole(0);
else if (version == '12.2(15)T8')
  security_hole(0);
else if (version == '12.2(15)T7')
  security_hole(0);
else if (version == '12.2(15)T5')
  security_hole(0);
else if (version == '12.2(15)T2')
  security_hole(0);
else if (version == '12.2(15)T16')
  security_hole(0);
else if (version == '12.2(15)T15')
  security_hole(0);
else if (version == '12.2(15)T14')
  security_hole(0);
else if (version == '12.2(15)T13')
  security_hole(0);
else if (version == '12.2(15)T12')
  security_hole(0);
else if (version == '12.2(15)T11')
  security_hole(0);
else if (version == '12.2(15)T10')
  security_hole(0);
else if (version == '12.2(15)T1')
  security_hole(0);
else if (version == '12.2(15)T')
  security_hole(0);
else if (version == '12.2(13)T9')
  security_hole(0);
else if (version == '12.2(13)T8')
  security_hole(0);
else if (version == '12.2(13)T5')
  security_hole(0);
else if (version == '12.2(13)T4')
  security_hole(0);
else if (version == '12.2(13)T3')
  security_hole(0);
else if (version == '12.2(13)T16')
  security_hole(0);
else if (version == '12.2(13)T14')
  security_hole(0);
else if (version == '12.2(13)T13')
  security_hole(0);
else if (version == '12.2(13)T12')
  security_hole(0);
else if (version == '12.2(13)T11')
  security_hole(0);
else if (version == '12.2(13)T10')
  security_hole(0);
else if (version == '12.2(13)T1a')
  security_hole(0);
else if (version == '12.2(13)T1')
  security_hole(0);
else if (version == '12.2(13)T')
  security_hole(0);
else if (version == '12.2(11)T9')
  security_hole(0);
else if (version == '12.2(11)T8')
  security_hole(0);
else if (version == '12.2(11)T6')
  security_hole(0);
else if (version == '12.2(11)T5')
  security_hole(0);
else if (version == '12.2(11)T3')
  security_hole(0);
else if (version == '12.2(11)T2')
  security_hole(0);
else if (version == '12.2(11)T11')
  security_hole(0);
else if (version == '12.2(11)T10')
  security_hole(0);
else if (version == '12.2(11)T1')
  security_hole(0);
else if (version == '12.2(11)T')
  security_hole(0);
else if (version == '12.2(8)T5')
  security_hole(0);
else if (version == '12.2(8)T4')
  security_hole(0);
else if (version == '12.2(8)T10')
  security_hole(0);
else if (version == '12.2(8)T1')
  security_hole(0);
else if (version == '12.2(8)T')
  security_hole(0);
else if (version == '12.2(4)T7')
  security_hole(0);
else if (version == '12.2(4)T3')
  security_hole(0);
else if (version == '12.2(4)T2')
  security_hole(0);
else if (version == '12.2(4)T1')
  security_hole(0);
else if (version == '12.2(4)T')
  security_hole(0);
else if (version == '12.2(2)T4')
  security_hole(0);
else if (version == '12.2(2)T1')
  security_hole(0);
else if (version == '12.2(2)T')
  security_hole(0);
else if (version == '12.2(12h)M1')
  security_hole(0);
else if (version == '12.2(12b)M1')
  security_hole(0);
else if (version == '12.2(6c)M1')
  security_hole(0);
else if (version == '12.2(40)')
  security_hole(0);
else if (version == '12.2(37)')
  security_hole(0);
else if (version == '12.2(34a)')
  security_hole(0);
else if (version == '12.2(34)')
  security_hole(0);
else if (version == '12.2(32)')
  security_hole(0);
else if (version == '12.2(31)')
  security_hole(0);
else if (version == '12.2(29a)')
  security_hole(0);
else if (version == '12.2(29)')
  security_hole(0);
else if (version == '12.2(28c)')
  security_hole(0);
else if (version == '12.2(28b)')
  security_hole(0);
else if (version == '12.2(28a)')
  security_hole(0);
else if (version == '12.2(28)')
  security_hole(0);
else if (version == '12.2(27b)')
  security_hole(0);
else if (version == '12.2(27a)')
  security_hole(0);
else if (version == '12.2(27)')
  security_hole(0);
else if (version == '12.2(26b)')
  security_hole(0);
else if (version == '12.2(26a)')
  security_hole(0);
else if (version == '12.2(26)')
  security_hole(0);
else if (version == '12.2(24b)')
  security_hole(0);
else if (version == '12.2(24a)')
  security_hole(0);
else if (version == '12.2(24)')
  security_hole(0);
else if (version == '12.2(23f)')
  security_hole(0);
else if (version == '12.2(23e)')
  security_hole(0);
else if (version == '12.2(23d)')
  security_hole(0);
else if (version == '12.2(23c)')
  security_hole(0);
else if (version == '12.2(23a)')
  security_hole(0);
else if (version == '12.2(23)')
  security_hole(0);
else if (version == '12.2(21b)')
  security_hole(0);
else if (version == '12.2(21a)')
  security_hole(0);
else if (version == '12.2(21)')
  security_hole(0);
else if (version == '12.2(19c)')
  security_hole(0);
else if (version == '12.2(19b)')
  security_hole(0);
else if (version == '12.2(19a)')
  security_hole(0);
else if (version == '12.2(19)')
  security_hole(0);
else if (version == '12.2(17f)')
  security_hole(0);
else if (version == '12.2(17e)')
  security_hole(0);
else if (version == '12.2(17d)')
  security_hole(0);
else if (version == '12.2(17b)')
  security_hole(0);
else if (version == '12.2(17a)')
  security_hole(0);
else if (version == '12.2(17)')
  security_hole(0);
else if (version == '12.2(16f)')
  security_hole(0);
else if (version == '12.2(16c)')
  security_hole(0);
else if (version == '12.2(16b)')
  security_hole(0);
else if (version == '12.2(16a)')
  security_hole(0);
else if (version == '12.2(16)')
  security_hole(0);
else if (version == '12.2(13e)')
  security_hole(0);
else if (version == '12.2(13c)')
  security_hole(0);
else if (version == '12.2(13b)')
  security_hole(0);
else if (version == '12.2(13a)')
  security_hole(0);
else if (version == '12.2(13)')
  security_hole(0);
else if (version == '12.2(12m)')
  security_hole(0);
else if (version == '12.2(12l)')
  security_hole(0);
else if (version == '12.2(12k)')
  security_hole(0);
else if (version == '12.2(12j)')
  security_hole(0);
else if (version == '12.2(12i)')
  security_hole(0);
else if (version == '12.2(12h)')
  security_hole(0);
else if (version == '12.2(12g)')
  security_hole(0);
else if (version == '12.2(12f)')
  security_hole(0);
else if (version == '12.2(12e)')
  security_hole(0);
else if (version == '12.2(12c)')
  security_hole(0);
else if (version == '12.2(12b)')
  security_hole(0);
else if (version == '12.2(12a)')
  security_hole(0);
else if (version == '12.2(12)')
  security_hole(0);
else if (version == '12.2(10g)')
  security_hole(0);
else if (version == '12.2(10d)')
  security_hole(0);
else if (version == '12.2(10b)')
  security_hole(0);
else if (version == '12.2(10a)')
  security_hole(0);
else if (version == '12.2(10)')
  security_hole(0);
else if (version == '12.2(7g)')
  security_hole(0);
else if (version == '12.2(7c)')
  security_hole(0);
else if (version == '12.2(7b)')
  security_hole(0);
else if (version == '12.2(7a)')
  security_hole(0);
else if (version == '12.2(7)')
  security_hole(0);
else if (version == '12.2(6j)')
  security_hole(0);
else if (version == '12.2(6i)')
  security_hole(0);
else if (version == '12.2(6h)')
  security_hole(0);
else if (version == '12.2(6g)')
  security_hole(0);
else if (version == '12.2(6f)')
  security_hole(0);
else if (version == '12.2(6e)')
  security_hole(0);
else if (version == '12.2(6d)')
  security_hole(0);
else if (version == '12.2(6c)')
  security_hole(0);
else if (version == '12.2(6b)')
  security_hole(0);
else if (version == '12.2(6a)')
  security_hole(0);
else if (version == '12.2(6)')
  security_hole(0);
else if (version == '12.2(5d)')
  security_hole(0);
else if (version == '12.2(5a)')
  security_hole(0);
else if (version == '12.2(5)')
  security_hole(0);
else if (version == '12.2(3g)')
  security_hole(0);
else if (version == '12.2(3c)')
  security_hole(0);
else if (version == '12.2(3b)')
  security_hole(0);
else if (version == '12.2(3a)')
  security_hole(0);
else if (version == '12.2(3)')
  security_hole(0);
else if (version == '12.2(1d)')
  security_hole(0);
else if (version == '12.2(1c)')
  security_hole(0);
else if (version == '12.2(1b)')
  security_hole(0);
else if (version == '12.2(1a)')
  security_hole(0);
else if (version == '12.2(1)')
  security_hole(0);
else if (version == '12.1(5)XM8')
  security_hole(0);
else if (version == '12.1(5)XM7')
  security_hole(0);
else if (version == '12.1(5)XM5')
  security_hole(0);
else if (version == '12.1(5)XM4')
  security_hole(0);
else if (version == '12.1(5)XM3')
  security_hole(0);
else if (version == '12.1(5)XM2')
  security_hole(0);
else if (version == '12.1(5)XM1')
  security_hole(0);
else if (version == '12.1(5)XM')
  security_hole(0);
else if (version == '12.1(2a)XH3')
  security_hole(0);
else if (version == '12.1(2a)XH2')
  security_hole(0);
else if (version == '12.1(2a)XH')
  security_hole(0);
else if (version == '12.1(5)T9')
  security_hole(0);
else if (version == '12.1(5)T8')
  security_hole(0);
else if (version == '12.1(5)T7')
  security_hole(0);
else if (version == '12.1(5)T6')
  security_hole(0);
else if (version == '12.1(5)T5')
  security_hole(0);
else if (version == '12.1(5)T4')
  security_hole(0);
else if (version == '12.1(5)T19')
  security_hole(0);
else if (version == '12.1(5)T18')
  security_hole(0);
else if (version == '12.1(5)T17')
  security_hole(0);
else if (version == '12.1(5)T15')
  security_hole(0);
else if (version == '12.1(5)T12')
  security_hole(0);
else if (version == '12.1(5)T10')
  security_hole(0);
else if (version == '12.1(5)T')
  security_hole(0);
else if (version == '12.1(3)T')
  security_hole(0);
else if (version == '12.1(2)T')
  security_hole(0);
else if (version == '12.1(1)T')
  security_hole(0);
else if (version == '12.1(27b)')
  security_hole(0);
else if (version == '12.1(27a)')
  security_hole(0);
else if (version == '12.1(27)')
  security_hole(0);
else if (version == '12.1(25)')
  security_hole(0);
else if (version == '12.1(24)')
  security_hole(0);
else if (version == '12.1(22c)')
  security_hole(0);
else if (version == '12.1(22b)')
  security_hole(0);
else if (version == '12.1(22a)')
  security_hole(0);
else if (version == '12.1(22)')
  security_hole(0);
else if (version == '12.1(21)')
  security_hole(0);
else if (version == '12.1(20a)')
  security_hole(0);
else if (version == '12.1(20)')
  security_hole(0);
else if (version == '12.1(19)')
  security_hole(0);
else if (version == '12.1(18)')
  security_hole(0);
else if (version == '12.1(17a)')
  security_hole(0);
else if (version == '12.1(17)')
  security_hole(0);
else if (version == '12.1(16)')
  security_hole(0);
else if (version == '12.1(15)')
  security_hole(0);
else if (version == '12.1(14)')
  security_hole(0);
else if (version == '12.1(13a)')
  security_hole(0);
else if (version == '12.1(13)')
  security_hole(0);
else if (version == '12.1(12b)')
  security_hole(0);
else if (version == '12.1(12a)')
  security_hole(0);
else if (version == '12.1(12)')
  security_hole(0);
else if (version == '12.1(11b)')
  security_hole(0);
else if (version == '12.1(11)')
  security_hole(0);
else if (version == '12.1(10a)')
  security_hole(0);
else if (version == '12.1(10)')
  security_hole(0);
else if (version == '12.1(9a)')
  security_hole(0);
else if (version == '12.1(9)')
  security_hole(0);
else if (version == '12.1(8a)')
  security_hole(0);
else if (version == '12.1(8)')
  security_hole(0);
else if (version == '12.1(7c)')
  security_hole(0);
else if (version == '12.1(7b)')
  security_hole(0);
else if (version == '12.1(7)')
  security_hole(0);
else if (version == '12.1(6b)')
  security_hole(0);
else if (version == '12.1(6a)')
  security_hole(0);
else if (version == '12.1(6)')
  security_hole(0);
else if (version == '12.1(5e)')
  security_hole(0);
else if (version == '12.1(5c)')
  security_hole(0);
else if (version == '12.1(5)')
  security_hole(0);
else if (version == '12.1(4c)')
  security_hole(0);
else if (version == '12.1(4b)')
  security_hole(0);
else if (version == '12.1(4a)')
  security_hole(0);
else if (version == '12.1(3b)')
  security_hole(0);
else if (version == '12.1(3)')
  security_hole(0);
else if (version == '12.1(2b)')
  security_hole(0);
else if (version == '12.1(2)')
  security_hole(0);
else if (version == '12.1(1c)')
  security_hole(0);
else if (version == '12.1(1)')
  security_hole(0);
else if (version == '12.0(7)XK3')
  security_hole(0);
else if (version == '12.0(7)XK2')
  security_hole(0);
else if (version == '12.0(7)XK1')
  security_hole(0);
else if (version == '12.0(5)XK2')
  security_hole(0);
else if (version == '12.0(5)XK1')
  security_hole(0);
else if (version == '12.0(5)XK')
  security_hole(0);
else if (version == '12.0(2)XC2')
  security_hole(0);
else if (version == '12.0(2)XC1')
  security_hole(0);
else if (version == '12.0(2)XC')
  security_hole(0);
else if (version == '12.0(7)T3')
  security_hole(0);
else if (version == '12.0(7)T2')
  security_hole(0);
else if (version == '12.0(7)T')
  security_hole(0);
else if (version == '12.0(5)T1')
  security_hole(0);
else if (version == '12.0(5)T')
  security_hole(0);
else if (version == '12.0(4)T')
  security_hole(0);
else if (version == '12.0(3)T2')
  security_hole(0);
else if (version == '12.0(3)T')
  security_hole(0);
else if (version == '12.0(2a)T1')
  security_hole(0);
else if (version == '12.0(2)T')
  security_hole(0);
else if (version == '12.0(1)T')
  security_hole(0);
else if (version == '12.0(7a)')
  security_hole(0);
else if (version == '12.0(7)')
  security_hole(0);
else if (version == '12.0(6b)')
  security_hole(0);
else if (version == '12.0(6a)')
  security_hole(0);
else if (version == '12.0(6)')
  security_hole(0);
else if (version == '12.0(5a)')
  security_hole(0);
else if (version == '12.0(5)')
  security_hole(0);
else if (version == '12.0(4b)')
  security_hole(0);
else if (version == '12.0(4)')
  security_hole(0);
else if (version == '12.0(3d)')
  security_hole(0);
else if (version == '12.0(3c)')
  security_hole(0);
else if (version == '12.0(3b)')
  security_hole(0);
else if (version == '12.0(3)')
  security_hole(0);
else if (version == '12.0(2b)')
  security_hole(0);
else if (version == '12.0(2a)')
  security_hole(0);
else if (version == '12.0(2)')
  security_hole(0);
else if (version == '12.0(1)')
  security_hole(0);
else
  exit(0, 'The host is not affected.');

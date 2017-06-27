#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080af511d.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49038);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2008-4609", "CVE-2009-0627");
 script_bugtraq_id(31545, 36303);
 script_osvdb_id(50286);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv02768");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv04836");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv07712");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv08059");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv08325");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv08579");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv66169");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090908-tcp24");
 script_name(english:"TCP State Manipulation Denial of Service Vulnerabilities in Multiple Cisco Products - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'Multiple Cisco products are affected by denial of service (DoS)
vulnerabilities that manipulate the state of Transmission Control
Protocol (TCP) connections. By manipulating the state of a TCP
connection, an attacker could force the TCP connection to remain in a
long-lived state, possibly indefinitely. If enough TCP connections are
forced into a long-lived or indefinite state, resources on a system
under attack may be consumed, preventing new TCP connections from being
accepted. In some cases, a system reboot may be necessary to recover
normal system operation. To exploit these vulnerabilities, an attacker
must be able to complete a TCP three-way handshake with a vulnerable
system.
In addition to these vulnerabilities, Cisco Nexus 5000 devices contain
a TCP DoS vulnerability that may result in a system crash. This
additional vulnerability was found as a result of testing the TCP state
manipulation vulnerabilities.
Cisco has released free software updates for download from the Cisco
website that address these vulnerabilities. Workarounds that mitigate
these vulnerabilities are available.
');
 script_set_attribute(attribute:"see_also", value: "https://www.cert.fi/haavoittuvuudet/2008/tcp-vulnerabilities.html");
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?c44442a0");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080af511d.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?12cf8d1c");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090908-tcp24."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16);
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2008/10/02"); # first announced at now-defunct URL http://www.outpost24.com/news/news-2008-10-02.html
 script_set_attribute(attribute:"patch_publication_date", value: "2009/09/08");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
 script_end_attributes();
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}
include("cisco_func.inc");

#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(20)YA1')
  security_hole(0);
else if (version == '12.4(20)YA')
  security_hole(0);
else if (version == '12.4(15)XZ1')
  security_hole(0);
else if (version == '12.4(15)XZ')
  security_hole(0);
else if (version == '12.4(15)XY4')
  security_hole(0);
else if (version == '12.4(15)XY3')
  security_hole(0);
else if (version == '12.4(15)XY2')
  security_hole(0);
else if (version == '12.4(15)XY1')
  security_hole(0);
else if (version == '12.4(15)XY')
  security_hole(0);
else if (version == '12.4(11)XW9')
  security_hole(0);
else if (version == '12.4(11)XW8')
  security_hole(0);
else if (version == '12.4(11)XW7')
  security_hole(0);
else if (version == '12.4(11)XW6')
  security_hole(0);
else if (version == '12.4(11)XW5')
  security_hole(0);
else if (version == '12.4(11)XW4')
  security_hole(0);
else if (version == '12.4(11)XW3')
  security_hole(0);
else if (version == '12.4(11)XW2')
  security_hole(0);
else if (version == '12.4(11)XW1')
  security_hole(0);
else if (version == '12.4(11)XW')
  security_hole(0);
else if (version == '12.4(11)XV1')
  security_hole(0);
else if (version == '12.4(11)XV')
  security_hole(0);
else if (version == '12.4(6)XT2')
  security_hole(0);
else if (version == '12.4(6)XT1')
  security_hole(0);
else if (version == '12.4(6)XT')
  security_hole(0);
else if (version == '12.4(15)XR3')
  security_hole(0);
else if (version == '12.4(15)XR2')
  security_hole(0);
else if (version == '12.4(15)XR1')
  security_hole(0);
else if (version == '12.4(15)XR')
  security_hole(0);
else if (version == '12.4(15)XQ1')
  security_hole(0);
else if (version == '12.4(15)XQ')
  security_hole(0);
else if (version == '12.4(6)XP')
  security_hole(0);
else if (version == '12.4(15)XN')
  security_hole(0);
else if (version == '12.4(15)XM2')
  security_hole(0);
else if (version == '12.4(15)XM1')
  security_hole(0);
else if (version == '12.4(15)XM')
  security_hole(0);
else if (version == '12.4(15)XL3')
  security_hole(0);
else if (version == '12.4(15)XL2')
  security_hole(0);
else if (version == '12.4(15)XL1')
  security_hole(0);
else if (version == '12.4(15)XL')
  security_hole(0);
else if (version == '12.4(14)XK')
  security_hole(0);
else if (version == '12.4(11)XJ4')
  security_hole(0);
else if (version == '12.4(11)XJ3')
  security_hole(0);
else if (version == '12.4(11)XJ2')
  security_hole(0);
else if (version == '12.4(11)XJ')
  security_hole(0);
else if (version == '12.4(9)XG3')
  security_hole(0);
else if (version == '12.4(9)XG2')
  security_hole(0);
else if (version == '12.4(9)XG1')
  security_hole(0);
else if (version == '12.4(9)XG')
  security_hole(0);
else if (version == '12.4(15)XF')
  security_hole(0);
else if (version == '12.4(6)XE3')
  security_hole(0);
else if (version == '12.4(6)XE2')
  security_hole(0);
else if (version == '12.4(6)XE1')
  security_hole(0);
else if (version == '12.4(6)XE')
  security_hole(0);
else if (version == '12.4(4)XD9')
  security_hole(0);
else if (version == '12.4(4)XD8')
  security_hole(0);
else if (version == '12.4(4)XD7')
  security_hole(0);
else if (version == '12.4(4)XD5')
  security_hole(0);
else if (version == '12.4(4)XD4')
  security_hole(0);
else if (version == '12.4(4)XD2')
  security_hole(0);
else if (version == '12.4(4)XD11')
  security_hole(0);
else if (version == '12.4(4)XD10')
  security_hole(0);
else if (version == '12.4(4)XD1')
  security_hole(0);
else if (version == '12.4(4)XD')
  security_hole(0);
else if (version == '12.4(4)XC7')
  security_hole(0);
else if (version == '12.4(4)XC6')
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
else if (version == '12.4(2)XB9')
  security_hole(0);
else if (version == '12.4(2)XB8')
  security_hole(0);
else if (version == '12.4(2)XB7')
  security_hole(0);
else if (version == '12.4(2)XB6')
  security_hole(0);
else if (version == '12.4(2)XB5')
  security_hole(0);
else if (version == '12.4(2)XB4')
  security_hole(0);
else if (version == '12.4(2)XB3')
  security_hole(0);
else if (version == '12.4(2)XB2')
  security_hole(0);
else if (version == '12.4(2)XB10')
  security_hole(0);
else if (version == '12.4(2)XB1')
  security_hole(0);
else if (version == '12.4(2)XB')
  security_hole(0);
else if (version == '12.4(2)XA2')
  security_hole(0);
else if (version == '12.4(2)XA1')
  security_hole(0);
else if (version == '12.4(2)XA')
  security_hole(0);
else if (version == '12.4(22)T')
  security_hole(0);
else if (version == '12.4(20)T1')
  security_hole(0);
else if (version == '12.4(20)T')
  security_hole(0);
else if (version == '12.4(15)T7')
  security_hole(0);
else if (version == '12.4(15)T6')
  security_hole(0);
else if (version == '12.4(15)T5')
  security_hole(0);
else if (version == '12.4(15)T4')
  security_hole(0);
else if (version == '12.4(15)T3')
  security_hole(0);
else if (version == '12.4(15)T2')
  security_hole(0);
else if (version == '12.4(15)T1')
  security_hole(0);
else if (version == '12.4(15)T')
  security_hole(0);
else if (version == '12.4(11)T4')
  security_hole(0);
else if (version == '12.4(11)T3')
  security_hole(0);
else if (version == '12.4(11)T2')
  security_hole(0);
else if (version == '12.4(11)T1')
  security_hole(0);
else if (version == '12.4(11)T')
  security_hole(0);
else if (version == '12.4(9)T7')
  security_hole(0);
else if (version == '12.4(9)T6')
  security_hole(0);
else if (version == '12.4(9)T5')
  security_hole(0);
else if (version == '12.4(9)T4')
  security_hole(0);
else if (version == '12.4(9)T3')
  security_hole(0);
else if (version == '12.4(9)T2')
  security_hole(0);
else if (version == '12.4(9)T1')
  security_hole(0);
else if (version == '12.4(9)T')
  security_hole(0);
else if (version == '12.4(6)T9')
  security_hole(0);
else if (version == '12.4(6)T8')
  security_hole(0);
else if (version == '12.4(6)T7')
  security_hole(0);
else if (version == '12.4(6)T6')
  security_hole(0);
else if (version == '12.4(6)T5')
  security_hole(0);
else if (version == '12.4(6)T4')
  security_hole(0);
else if (version == '12.4(6)T3')
  security_hole(0);
else if (version == '12.4(6)T2')
  security_hole(0);
else if (version == '12.4(6)T11')
  security_hole(0);
else if (version == '12.4(6)T10')
  security_hole(0);
else if (version == '12.4(6)T1')
  security_hole(0);
else if (version == '12.4(6)T')
  security_hole(0);
else if (version == '12.4(4)T8')
  security_hole(0);
else if (version == '12.4(4)T7')
  security_hole(0);
else if (version == '12.4(4)T6')
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
else if (version == '12.4(2)T6')
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
else if (version == '12.4(15)SW2')
  security_hole(0);
else if (version == '12.4(15)SW1')
  security_hole(0);
else if (version == '12.4(15)SW')
  security_hole(0);
else if (version == '12.4(11)SW3')
  security_hole(0);
else if (version == '12.4(11)SW2')
  security_hole(0);
else if (version == '12.4(11)SW1')
  security_hole(0);
else if (version == '12.4(11)SW')
  security_hole(0);
else if (version == '12.4(22)MX')
  security_hole(0);
else if (version == '12.4(19)MR')
  security_hole(0);
else if (version == '12.4(16)MR2')
  security_hole(0);
else if (version == '12.4(16)MR1')
  security_hole(0);
else if (version == '12.4(16)MR')
  security_hole(0);
else if (version == '12.4(12)MR2')
  security_hole(0);
else if (version == '12.4(12)MR1')
  security_hole(0);
else if (version == '12.4(12)MR')
  security_hole(0);
else if (version == '12.4(11)MR')
  security_hole(0);
else if (version == '12.4(9)MR')
  security_hole(0);
else if (version == '12.4(6)MR1')
  security_hole(0);
else if (version == '12.4(6)MR')
  security_hole(0);
else if (version == '12.4(4)MR1')
  security_hole(0);
else if (version == '12.4(4)MR')
  security_hole(0);
else if (version == '12.4(2)MR1')
  security_hole(0);
else if (version == '12.4(2)MR')
  security_hole(0);
else if (version == '12.4(15)MD1')
  security_hole(0);
else if (version == '12.4(15)MD')
  security_hole(0);
else if (version == '12.4(11)MD6')
  security_hole(0);
else if (version == '12.4(11)MD5')
  security_hole(0);
else if (version == '12.4(11)MD4')
  security_hole(0);
else if (version == '12.4(11)MD3')
  security_hole(0);
else if (version == '12.4(11)MD2')
  security_hole(0);
else if (version == '12.4(11)MD1')
  security_hole(0);
else if (version == '12.4(11)MD')
  security_hole(0);
else if (version == '12.4(10b)JX')
  security_hole(0);
else if (version == '12.4(3g)JX2')
  security_hole(0);
else if (version == '12.4(3g)JX1')
  security_hole(0);
else if (version == '12.4(3g)JX')
  security_hole(0);
else if (version == '12.4(3g)JMC2')
  security_hole(0);
else if (version == '12.4(3g)JMC1')
  security_hole(0);
else if (version == '12.4(3g)JMC')
  security_hole(0);
else if (version == '12.4(3g)JMB')
  security_hole(0);
else if (version == '12.4(3g)JMA1')
  security_hole(0);
else if (version == '12.4(3g)JMA')
  security_hole(0);
else if (version == '12.4(3)JL')
  security_hole(0);
else if (version == '12.4(3)JK3')
  security_hole(0);
else if (version == '12.4(3)JK2')
  security_hole(0);
else if (version == '12.4(3)JK1')
  security_hole(0);
else if (version == '12.4(3)JK')
  security_hole(0);
else if (version == '12.4(10b)JDA2')
  security_hole(0);
else if (version == '12.4(10b)JDA1')
  security_hole(0);
else if (version == '12.4(10b)JDA')
  security_hole(0);
else if (version == '12.4(18a)JA')
  security_hole(0);
else if (version == '12.4(16b)JA')
  security_hole(0);
else if (version == '12.4(13d)JA')
  security_hole(0);
else if (version == '12.4(10b)JA4')
  security_hole(0);
else if (version == '12.4(10b)JA3')
  security_hole(0);
else if (version == '12.4(10b)JA2')
  security_hole(0);
else if (version == '12.4(10b)JA1')
  security_hole(0);
else if (version == '12.4(10b)JA')
  security_hole(0);
else if (version == '12.4(3g)JA2')
  security_hole(0);
else if (version == '12.4(3g)JA1')
  security_hole(0);
else if (version == '12.4(3g)JA')
  security_hole(0);
else if (version == '12.4(23)')
  security_hole(0);
else if (version == '12.4(21a)')
  security_hole(0);
else if (version == '12.4(21)')
  security_hole(0);
else if (version == '12.4(19b)')
  security_hole(0);
else if (version == '12.4(19a)')
  security_hole(0);
else if (version == '12.4(19)')
  security_hole(0);
else if (version == '12.4(18c)')
  security_hole(0);
else if (version == '12.4(18b)')
  security_hole(0);
else if (version == '12.4(18a)')
  security_hole(0);
else if (version == '12.4(18)')
  security_hole(0);
else if (version == '12.4(17b)')
  security_hole(0);
else if (version == '12.4(17a)')
  security_hole(0);
else if (version == '12.4(17)')
  security_hole(0);
else if (version == '12.4(16b)')
  security_hole(0);
else if (version == '12.4(16a)')
  security_hole(0);
else if (version == '12.4(16)')
  security_hole(0);
else if (version == '12.4(13f)')
  security_hole(0);
else if (version == '12.4(13e)')
  security_hole(0);
else if (version == '12.4(13d)')
  security_hole(0);
else if (version == '12.4(13c)')
  security_hole(0);
else if (version == '12.4(13b)')
  security_hole(0);
else if (version == '12.4(13a)')
  security_hole(0);
else if (version == '12.4(13)')
  security_hole(0);
else if (version == '12.4(12c)')
  security_hole(0);
else if (version == '12.4(12b)')
  security_hole(0);
else if (version == '12.4(12a)')
  security_hole(0);
else if (version == '12.4(12)')
  security_hole(0);
else if (version == '12.4(10c)')
  security_hole(0);
else if (version == '12.4(10b)')
  security_hole(0);
else if (version == '12.4(10a)')
  security_hole(0);
else if (version == '12.4(10)')
  security_hole(0);
else if (version == '12.4(8d)')
  security_hole(0);
else if (version == '12.4(8c)')
  security_hole(0);
else if (version == '12.4(8b)')
  security_hole(0);
else if (version == '12.4(8a)')
  security_hole(0);
else if (version == '12.4(8)')
  security_hole(0);
else if (version == '12.4(7h)')
  security_hole(0);
else if (version == '12.4(7g)')
  security_hole(0);
else if (version == '12.4(7f)')
  security_hole(0);
else if (version == '12.4(7e)')
  security_hole(0);
else if (version == '12.4(7d)')
  security_hole(0);
else if (version == '12.4(7c)')
  security_hole(0);
else if (version == '12.4(7b)')
  security_hole(0);
else if (version == '12.4(7a)')
  security_hole(0);
else if (version == '12.4(7)')
  security_hole(0);
else if (version == '12.4(5c)')
  security_hole(0);
else if (version == '12.4(5b)')
  security_hole(0);
else if (version == '12.4(5a)')
  security_hole(0);
else if (version == '12.4(5)')
  security_hole(0);
else if (version == '12.4(3j)')
  security_hole(0);
else if (version == '12.4(3i)')
  security_hole(0);
else if (version == '12.4(3h)')
  security_hole(0);
else if (version == '12.4(3g)')
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
else if (version == '12.3(11)YZ2')
  security_hole(0);
else if (version == '12.3(11)YZ1')
  security_hole(0);
else if (version == '12.3(11)YZ')
  security_hole(0);
else if (version == '12.3(14)YX9')
  security_hole(0);
else if (version == '12.3(14)YX8')
  security_hole(0);
else if (version == '12.3(14)YX7')
  security_hole(0);
else if (version == '12.3(14)YX4')
  security_hole(0);
else if (version == '12.3(14)YX3')
  security_hole(0);
else if (version == '12.3(14)YX2')
  security_hole(0);
else if (version == '12.3(14)YX13')
  security_hole(0);
else if (version == '12.3(14)YX12')
  security_hole(0);
else if (version == '12.3(14)YX11')
  security_hole(0);
else if (version == '12.3(14)YX10')
  security_hole(0);
else if (version == '12.3(14)YX1')
  security_hole(0);
else if (version == '12.3(14)YX')
  security_hole(0);
else if (version == '12.3(14)YU1')
  security_hole(0);
else if (version == '12.3(14)YU')
  security_hole(0);
else if (version == '12.3(14)YT1')
  security_hole(0);
else if (version == '12.3(14)YT')
  security_hole(0);
else if (version == '12.3(11)YS2')
  security_hole(0);
else if (version == '12.3(11)YS1')
  security_hole(0);
else if (version == '12.3(11)YS')
  security_hole(0);
else if (version == '12.3(14)YQ8')
  security_hole(0);
else if (version == '12.3(14)YQ7')
  security_hole(0);
else if (version == '12.3(14)YQ6')
  security_hole(0);
else if (version == '12.3(14)YQ5')
  security_hole(0);
else if (version == '12.3(14)YQ4')
  security_hole(0);
else if (version == '12.3(14)YQ3')
  security_hole(0);
else if (version == '12.3(14)YQ2')
  security_hole(0);
else if (version == '12.3(14)YQ1')
  security_hole(0);
else if (version == '12.3(14)YQ')
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
else if (version == '12.3(14)YM12')
  security_hole(0);
else if (version == '12.3(14)YM11')
  security_hole(0);
else if (version == '12.3(14)YM10')
  security_hole(0);
else if (version == '12.3(11)YK3')
  security_hole(0);
else if (version == '12.3(11)YK2')
  security_hole(0);
else if (version == '12.3(11)YK1')
  security_hole(0);
else if (version == '12.3(11)YK')
  security_hole(0);
else if (version == '12.3(11)YJ')
  security_hole(0);
else if (version == '12.3(8)YI3')
  security_hole(0);
else if (version == '12.3(8)YI2')
  security_hole(0);
else if (version == '12.3(8)YI1')
  security_hole(0);
else if (version == '12.3(8)YH')
  security_hole(0);
else if (version == '12.3(8)YG6')
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
else if (version == '12.3(11)YF4')
  security_hole(0);
else if (version == '12.3(11)YF3')
  security_hole(0);
else if (version == '12.3(11)YF2')
  security_hole(0);
else if (version == '12.3(11)YF1')
  security_hole(0);
else if (version == '12.3(11)YF')
  security_hole(0);
else if (version == '12.3(8)YD1')
  security_hole(0);
else if (version == '12.3(8)YD')
  security_hole(0);
else if (version == '12.3(8)YA1')
  security_hole(0);
else if (version == '12.3(8)YA')
  security_hole(0);
else if (version == '12.3(2)XZ2')
  security_hole(0);
else if (version == '12.3(2)XZ1')
  security_hole(0);
else if (version == '12.3(8)XY7')
  security_hole(0);
else if (version == '12.3(8)XY6')
  security_hole(0);
else if (version == '12.3(8)XY5')
  security_hole(0);
else if (version == '12.3(8)XY4')
  security_hole(0);
else if (version == '12.3(8)XY3')
  security_hole(0);
else if (version == '12.3(8)XY2')
  security_hole(0);
else if (version == '12.3(8)XY1')
  security_hole(0);
else if (version == '12.3(8)XY')
  security_hole(0);
else if (version == '12.3(8)XX2d')
  security_hole(0);
else if (version == '12.3(8)XX1')
  security_hole(0);
else if (version == '12.3(8)XX')
  security_hole(0);
else if (version == '12.3(8)XW3')
  security_hole(0);
else if (version == '12.3(8)XW2')
  security_hole(0);
else if (version == '12.3(8)XW1')
  security_hole(0);
else if (version == '12.3(8)XW')
  security_hole(0);
else if (version == '12.3(8)XU5')
  security_hole(0);
else if (version == '12.3(8)XU4')
  security_hole(0);
else if (version == '12.3(8)XU3')
  security_hole(0);
else if (version == '12.3(8)XU2')
  security_hole(0);
else if (version == '12.3(8)XU1')
  security_hole(0);
else if (version == '12.3(8)XU')
  security_hole(0);
else if (version == '12.3(7)XS2')
  security_hole(0);
else if (version == '12.3(7)XS1')
  security_hole(0);
else if (version == '12.3(7)XS')
  security_hole(0);
else if (version == '12.3(7)XR7')
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
else if (version == '12.3(7)XJ2')
  security_hole(0);
else if (version == '12.3(7)XJ1')
  security_hole(0);
else if (version == '12.3(7)XJ')
  security_hole(0);
else if (version == '12.3(7)XI9')
  security_hole(0);
else if (version == '12.3(7)XI8d')
  security_hole(0);
else if (version == '12.3(7)XI8c')
  security_hole(0);
else if (version == '12.3(7)XI8a')
  security_hole(0);
else if (version == '12.3(7)XI8')
  security_hole(0);
else if (version == '12.3(7)XI7b')
  security_hole(0);
else if (version == '12.3(7)XI7a')
  security_hole(0);
else if (version == '12.3(7)XI7')
  security_hole(0);
else if (version == '12.3(7)XI6')
  security_hole(0);
else if (version == '12.3(7)XI5')
  security_hole(0);
else if (version == '12.3(7)XI4')
  security_hole(0);
else if (version == '12.3(7)XI3')
  security_hole(0);
else if (version == '12.3(7)XI2a')
  security_hole(0);
else if (version == '12.3(7)XI2')
  security_hole(0);
else if (version == '12.3(7)XI10a')
  security_hole(0);
else if (version == '12.3(7)XI10')
  security_hole(0);
else if (version == '12.3(7)XI1c')
  security_hole(0);
else if (version == '12.3(7)XI1b')
  security_hole(0);
else if (version == '12.3(7)XI1')
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
else if (version == '12.3(2)XE5')
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
else if (version == '12.3(2)XC5')
  security_hole(0);
else if (version == '12.3(2)XC4')
  security_hole(0);
else if (version == '12.3(2)XC3')
  security_hole(0);
else if (version == '12.3(2)XC2')
  security_hole(0);
else if (version == '12.3(2)XC1')
  security_hole(0);
else if (version == '12.3(2)XC')
  security_hole(0);
else if (version == '12.3(2)XB3')
  security_hole(0);
else if (version == '12.3(2)XB1')
  security_hole(0);
else if (version == '12.3(2)XB')
  security_hole(0);
else if (version == '12.3(2)XA7')
  security_hole(0);
else if (version == '12.3(2)XA6')
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
else if (version == '12.3(4)TPC11b')
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
else if (version == '12.3(4)T2a')
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
else if (version == '12.3(11)JX1')
  security_hole(0);
else if (version == '12.3(11)JX')
  security_hole(0);
else if (version == '12.3(7)JX9')
  security_hole(0);
else if (version == '12.3(7)JX8')
  security_hole(0);
else if (version == '12.3(7)JX7')
  security_hole(0);
else if (version == '12.3(7)JX6')
  security_hole(0);
else if (version == '12.3(7)JX5')
  security_hole(0);
else if (version == '12.3(7)JX4')
  security_hole(0);
else if (version == '12.3(7)JX3')
  security_hole(0);
else if (version == '12.3(7)JX2')
  security_hole(0);
else if (version == '12.3(7)JX11')
  security_hole(0);
else if (version == '12.3(7)JX10')
  security_hole(0);
else if (version == '12.3(7)JX1')
  security_hole(0);
else if (version == '12.3(7)JX')
  security_hole(0);
else if (version == '12.3(2)JL4')
  security_hole(0);
else if (version == '12.3(2)JL3')
  security_hole(0);
else if (version == '12.3(2)JL2')
  security_hole(0);
else if (version == '12.3(2)JL1')
  security_hole(0);
else if (version == '12.3(2)JL')
  security_hole(0);
else if (version == '12.3(8)JK1')
  security_hole(0);
else if (version == '12.3(2)JK3')
  security_hole(0);
else if (version == '12.3(2)JK2')
  security_hole(0);
else if (version == '12.3(2)JK1')
  security_hole(0);
else if (version == '12.3(2)JK')
  security_hole(0);
else if (version == '12.3(8)JEC2')
  security_hole(0);
else if (version == '12.3(8)JEC1')
  security_hole(0);
else if (version == '12.3(8)JEC')
  security_hole(0);
else if (version == '12.3(8)JEB2')
  security_hole(0);
else if (version == '12.3(8)JEB1')
  security_hole(0);
else if (version == '12.3(8)JEB')
  security_hole(0);
else if (version == '12.3(8)JEA3')
  security_hole(0);
else if (version == '12.3(8)JEA2')
  security_hole(0);
else if (version == '12.3(8)JEA1')
  security_hole(0);
else if (version == '12.3(8)JEA')
  security_hole(0);
else if (version == '12.3(11)JA4')
  security_hole(0);
else if (version == '12.3(11)JA3')
  security_hole(0);
else if (version == '12.3(11)JA2')
  security_hole(0);
else if (version == '12.3(11)JA1')
  security_hole(0);
else if (version == '12.3(11)JA')
  security_hole(0);
else if (version == '12.3(8)JA2')
  security_hole(0);
else if (version == '12.3(8)JA1')
  security_hole(0);
else if (version == '12.3(8)JA')
  security_hole(0);
else if (version == '12.3(7)JA5')
  security_hole(0);
else if (version == '12.3(7)JA4')
  security_hole(0);
else if (version == '12.3(7)JA3')
  security_hole(0);
else if (version == '12.3(7)JA2')
  security_hole(0);
else if (version == '12.3(7)JA1')
  security_hole(0);
else if (version == '12.3(7)JA')
  security_hole(0);
else if (version == '12.3(4)JA2')
  security_hole(0);
else if (version == '12.3(4)JA1')
  security_hole(0);
else if (version == '12.3(4)JA')
  security_hole(0);
else if (version == '12.3(2)JA6')
  security_hole(0);
else if (version == '12.3(2)JA5')
  security_hole(0);
else if (version == '12.3(2)JA2')
  security_hole(0);
else if (version == '12.3(2)JA1')
  security_hole(0);
else if (version == '12.3(2)JA')
  security_hole(0);
else if (version == '12.3(1a)BW')
  security_hole(0);
else if (version == '12.3(23)BC5')
  security_hole(0);
else if (version == '12.3(23)BC4')
  security_hole(0);
else if (version == '12.3(23)BC3')
  security_hole(0);
else if (version == '12.3(23)BC2')
  security_hole(0);
else if (version == '12.3(23)BC1')
  security_hole(0);
else if (version == '12.3(23)BC')
  security_hole(0);
else if (version == '12.3(21a)BC8')
  security_hole(0);
else if (version == '12.3(21a)BC7')
  security_hole(0);
else if (version == '12.3(21a)BC6')
  security_hole(0);
else if (version == '12.3(21a)BC5')
  security_hole(0);
else if (version == '12.3(21a)BC4')
  security_hole(0);
else if (version == '12.3(21a)BC3')
  security_hole(0);
else if (version == '12.3(21a)BC2')
  security_hole(0);
else if (version == '12.3(21a)BC1')
  security_hole(0);
else if (version == '12.3(21)BC')
  security_hole(0);
else if (version == '12.3(17b)BC9')
  security_hole(0);
else if (version == '12.3(17b)BC8')
  security_hole(0);
else if (version == '12.3(17b)BC7')
  security_hole(0);
else if (version == '12.3(17b)BC6')
  security_hole(0);
else if (version == '12.3(17b)BC5')
  security_hole(0);
else if (version == '12.3(17b)BC4')
  security_hole(0);
else if (version == '12.3(17b)BC3')
  security_hole(0);
else if (version == '12.3(17a)BC2')
  security_hole(0);
else if (version == '12.3(17a)BC1')
  security_hole(0);
else if (version == '12.3(17a)BC')
  security_hole(0);
else if (version == '12.3(13a)BC6')
  security_hole(0);
else if (version == '12.3(13a)BC5')
  security_hole(0);
else if (version == '12.3(13a)BC4')
  security_hole(0);
else if (version == '12.3(13a)BC3')
  security_hole(0);
else if (version == '12.3(13a)BC2')
  security_hole(0);
else if (version == '12.3(13a)BC1')
  security_hole(0);
else if (version == '12.3(13a)BC')
  security_hole(0);
else if (version == '12.3(9a)BC9')
  security_hole(0);
else if (version == '12.3(9a)BC8')
  security_hole(0);
else if (version == '12.3(9a)BC7')
  security_hole(0);
else if (version == '12.3(9a)BC6')
  security_hole(0);
else if (version == '12.3(9a)BC5')
  security_hole(0);
else if (version == '12.3(9a)BC4')
  security_hole(0);
else if (version == '12.3(9a)BC3')
  security_hole(0);
else if (version == '12.3(9a)BC2')
  security_hole(0);
else if (version == '12.3(9a)BC1')
  security_hole(0);
else if (version == '12.3(9a)BC')
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
else if (version == '12.3(26)')
  security_hole(0);
else if (version == '12.3(25)')
  security_hole(0);
else if (version == '12.3(24a)')
  security_hole(0);
else if (version == '12.3(24)')
  security_hole(0);
else if (version == '12.3(23)')
  security_hole(0);
else if (version == '12.3(22a)')
  security_hole(0);
else if (version == '12.3(22)')
  security_hole(0);
else if (version == '12.3(21b)')
  security_hole(0);
else if (version == '12.3(21)')
  security_hole(0);
else if (version == '12.3(20a)')
  security_hole(0);
else if (version == '12.3(20)')
  security_hole(0);
else if (version == '12.3(19a)')
  security_hole(0);
else if (version == '12.3(19)')
  security_hole(0);
else if (version == '12.3(18a)')
  security_hole(0);
else if (version == '12.3(18)')
  security_hole(0);
else if (version == '12.3(17c)')
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
else if (version == '12.2(18)ZYA')
  security_hole(0);
else if (version == '12.2(18)ZY2')
  security_hole(0);
else if (version == '12.2(18)ZY1')
  security_hole(0);
else if (version == '12.2(18)ZY')
  security_hole(0);
else if (version == '12.2(28)ZX')
  security_hole(0);
else if (version == '12.2(18)ZU2')
  security_hole(0);
else if (version == '12.2(18)ZU1')
  security_hole(0);
else if (version == '12.2(18)ZU')
  security_hole(0);
else if (version == '12.2(13)ZP4')
  security_hole(0);
else if (version == '12.2(13)ZP3')
  security_hole(0);
else if (version == '12.2(13)ZP2')
  security_hole(0);
else if (version == '12.2(13)ZP1')
  security_hole(0);
else if (version == '12.2(13)ZP')
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
else if (version == '12.2(13)ZH9')
  security_hole(0);
else if (version == '12.2(13)ZH8')
  security_hole(0);
else if (version == '12.2(13)ZH7')
  security_hole(0);
else if (version == '12.2(13)ZH6')
  security_hole(0);
else if (version == '12.2(13)ZH5')
  security_hole(0);
else if (version == '12.2(13)ZH4')
  security_hole(0);
else if (version == '12.2(13)ZH3')
  security_hole(0);
else if (version == '12.2(13)ZH2')
  security_hole(0);
else if (version == '12.2(13)ZH10')
  security_hole(0);
else if (version == '12.2(13)ZH1')
  security_hole(0);
else if (version == '12.2(13)ZH')
  security_hole(0);
else if (version == '12.2(13)ZG')
  security_hole(0);
else if (version == '12.2(13)ZF2')
  security_hole(0);
else if (version == '12.2(13)ZF1')
  security_hole(0);
else if (version == '12.2(13)ZF')
  security_hole(0);
else if (version == '12.2(13)ZE')
  security_hole(0);
else if (version == '12.2(13)ZD4')
  security_hole(0);
else if (version == '12.2(13)ZD3')
  security_hole(0);
else if (version == '12.2(13)ZD2')
  security_hole(0);
else if (version == '12.2(13)ZD1')
  security_hole(0);
else if (version == '12.2(13)ZD')
  security_hole(0);
else if (version == '12.2(13)ZC')
  security_hole(0);
else if (version == '12.2(11)ZC')
  security_hole(0);
else if (version == '12.2(8)ZB8')
  security_hole(0);
else if (version == '12.2(8)ZB7')
  security_hole(0);
else if (version == '12.2(8)ZB6')
  security_hole(0);
else if (version == '12.2(8)ZB5')
  security_hole(0);
else if (version == '12.2(8)ZB4a')
  security_hole(0);
else if (version == '12.2(8)ZB4')
  security_hole(0);
else if (version == '12.2(8)ZB3')
  security_hole(0);
else if (version == '12.2(8)ZB2')
  security_hole(0);
else if (version == '12.2(8)ZB1')
  security_hole(0);
else if (version == '12.2(8)ZB')
  security_hole(0);
else if (version == '12.2(14)ZA7')
  security_hole(0);
else if (version == '12.2(14)ZA6')
  security_hole(0);
else if (version == '12.2(14)ZA5')
  security_hole(0);
else if (version == '12.2(14)ZA4')
  security_hole(0);
else if (version == '12.2(14)ZA3')
  security_hole(0);
else if (version == '12.2(14)ZA2')
  security_hole(0);
else if (version == '12.2(14)ZA1')
  security_hole(0);
else if (version == '12.2(14)ZA')
  security_hole(0);
else if (version == '12.2(9)ZA')
  security_hole(0);
else if (version == '12.2(11)YZ2')
  security_hole(0);
else if (version == '12.2(11)YZ1')
  security_hole(0);
else if (version == '12.2(11)YZ')
  security_hole(0);
else if (version == '12.2(8)YY4')
  security_hole(0);
else if (version == '12.2(8)YY3')
  security_hole(0);
else if (version == '12.2(8)YY2')
  security_hole(0);
else if (version == '12.2(8)YY1')
  security_hole(0);
else if (version == '12.2(8)YY')
  security_hole(0);
else if (version == '12.2(11)YX1')
  security_hole(0);
else if (version == '12.2(11)YX')
  security_hole(0);
else if (version == '12.2(8)YW3')
  security_hole(0);
else if (version == '12.2(8)YW2')
  security_hole(0);
else if (version == '12.2(8)YW1')
  security_hole(0);
else if (version == '12.2(8)YW')
  security_hole(0);
else if (version == '12.2(11)YV1')
  security_hole(0);
else if (version == '12.2(11)YV')
  security_hole(0);
else if (version == '12.2(11)YU')
  security_hole(0);
else if (version == '12.2(11)YT2')
  security_hole(0);
else if (version == '12.2(11)YT1')
  security_hole(0);
else if (version == '12.2(11)YT')
  security_hole(0);
else if (version == '12.2(11)YR')
  security_hole(0);
else if (version == '12.2(11)YQ')
  security_hole(0);
else if (version == '12.2(11)YP3')
  security_hole(0);
else if (version == '12.2(8)YN1')
  security_hole(0);
else if (version == '12.2(8)YN')
  security_hole(0);
else if (version == '12.2(8)YM')
  security_hole(0);
else if (version == '12.2(8)YL')
  security_hole(0);
else if (version == '12.2(2)YK1')
  security_hole(0);
else if (version == '12.2(2)YK')
  security_hole(0);
else if (version == '12.2(8)YJ1')
  security_hole(0);
else if (version == '12.2(8)YJ')
  security_hole(0);
else if (version == '12.2(4)YH')
  security_hole(0);
else if (version == '12.2(4)YG')
  security_hole(0);
else if (version == '12.2(4)YF')
  security_hole(0);
else if (version == '12.2(9)YE')
  security_hole(0);
else if (version == '12.2(8)YD3')
  security_hole(0);
else if (version == '12.2(8)YD2')
  security_hole(0);
else if (version == '12.2(8)YD1')
  security_hole(0);
else if (version == '12.2(8)YD')
  security_hole(0);
else if (version == '12.2(2)YC4')
  security_hole(0);
else if (version == '12.2(2)YC3')
  security_hole(0);
else if (version == '12.2(2)YC2')
  security_hole(0);
else if (version == '12.2(2)YC1')
  security_hole(0);
else if (version == '12.2(2)YC')
  security_hole(0);
else if (version == '12.2(4)YB')
  security_hole(0);
else if (version == '12.2(4)YA9')
  security_hole(0);
else if (version == '12.2(4)YA8')
  security_hole(0);
else if (version == '12.2(4)YA7')
  security_hole(0);
else if (version == '12.2(4)YA6')
  security_hole(0);
else if (version == '12.2(4)YA5')
  security_hole(0);
else if (version == '12.2(4)YA4')
  security_hole(0);
else if (version == '12.2(4)YA3')
  security_hole(0);
else if (version == '12.2(4)YA2')
  security_hole(0);
else if (version == '12.2(4)YA12')
  security_hole(0);
else if (version == '12.2(4)YA11')
  security_hole(0);
else if (version == '12.2(4)YA10')
  security_hole(0);
else if (version == '12.2(4)YA1')
  security_hole(0);
else if (version == '12.2(4)YA')
  security_hole(0);
else if (version == '12.2(4)XW')
  security_hole(0);
else if (version == '12.2(4)XV5')
  security_hole(0);
else if (version == '12.2(4)XV4a')
  security_hole(0);
else if (version == '12.2(4)XV4')
  security_hole(0);
else if (version == '12.2(4)XV3')
  security_hole(0);
else if (version == '12.2(4)XV2')
  security_hole(0);
else if (version == '12.2(4)XV1')
  security_hole(0);
else if (version == '12.2(4)XV')
  security_hole(0);
else if (version == '12.2(2)XU')
  security_hole(0);
else if (version == '12.2(2)XT3')
  security_hole(0);
else if (version == '12.2(2)XT2')
  security_hole(0);
else if (version == '12.2(2)XT')
  security_hole(0);
else if (version == '12.2(1)XS2')
  security_hole(0);
else if (version == '12.2(1)XS1a')
  security_hole(0);
else if (version == '12.2(1)XS1')
  security_hole(0);
else if (version == '12.2(1)XS')
  security_hole(0);
else if (version == '12.2(15)XR2')
  security_hole(0);
else if (version == '12.2(15)XR1')
  security_hole(0);
else if (version == '12.2(15)XR')
  security_hole(0);
else if (version == '12.2(4)XR')
  security_hole(0);
else if (version == '12.2(2)XR')
  security_hole(0);
else if (version == '12.2(2)XQ1')
  security_hole(0);
else if (version == '12.2(2)XQ')
  security_hole(0);
else if (version == '12.2(40)XO')
  security_hole(0);
else if (version == '12.2(33)XN1')
  security_hole(0);
else if (version == '12.2(2)XN')
  security_hole(0);
else if (version == '12.2(4)XM4')
  security_hole(0);
else if (version == '12.2(4)XM3')
  security_hole(0);
else if (version == '12.2(4)XM2')
  security_hole(0);
else if (version == '12.2(4)XM1')
  security_hole(0);
else if (version == '12.2(4)XM')
  security_hole(0);
else if (version == '12.2(4)XL6')
  security_hole(0);
else if (version == '12.2(4)XL5')
  security_hole(0);
else if (version == '12.2(4)XL4')
  security_hole(0);
else if (version == '12.2(4)XL3')
  security_hole(0);
else if (version == '12.2(4)XL2')
  security_hole(0);
else if (version == '12.2(4)XL1')
  security_hole(0);
else if (version == '12.2(4)XL')
  security_hole(0);
else if (version == '12.2(2)XK3')
  security_hole(0);
else if (version == '12.2(2)XK2')
  security_hole(0);
else if (version == '12.2(2)XK1')
  security_hole(0);
else if (version == '12.2(2)XK')
  security_hole(0);
else if (version == '12.2(2)XJ')
  security_hole(0);
else if (version == '12.2(2)XI2')
  security_hole(0);
else if (version == '12.2(2)XI1')
  security_hole(0);
else if (version == '12.2(2)XI')
  security_hole(0);
else if (version == '12.2(2)XH2')
  security_hole(0);
else if (version == '12.2(2)XH1')
  security_hole(0);
else if (version == '12.2(2)XH')
  security_hole(0);
else if (version == '12.2(2)XG1')
  security_hole(0);
else if (version == '12.2(2)XG')
  security_hole(0);
else if (version == '12.2(4)XF1')
  security_hole(0);
else if (version == '12.2(4)XF')
  security_hole(0);
else if (version == '12.2(2)XF2')
  security_hole(0);
else if (version == '12.2(2)XF1')
  security_hole(0);
else if (version == '12.2(2)XF')
  security_hole(0);
else if (version == '12.2(1)XF1')
  security_hole(0);
else if (version == '12.2(1)XF')
  security_hole(0);
else if (version == '12.2(1)XE2')
  security_hole(0);
else if (version == '12.2(1)XE1')
  security_hole(0);
else if (version == '12.2(1)XE')
  security_hole(0);
else if (version == '12.2(1)XD4')
  security_hole(0);
else if (version == '12.2(1)XD3')
  security_hole(0);
else if (version == '12.2(1)XD2')
  security_hole(0);
else if (version == '12.2(1)XD1')
  security_hole(0);
else if (version == '12.2(1)XD')
  security_hole(0);
else if (version == '12.2(2)XC2')
  security_hole(0);
else if (version == '12.2(2)XC1')
  security_hole(0);
else if (version == '12.2(2)XC')
  security_hole(0);
else if (version == '12.2(1a)XC3')
  security_hole(0);
else if (version == '12.2(1a)XC2')
  security_hole(0);
else if (version == '12.2(1a)XC1')
  security_hole(0);
else if (version == '12.2(1a)XC')
  security_hole(0);
else if (version == '12.2(2)XB8')
  security_hole(0);
else if (version == '12.2(2)XB7')
  security_hole(0);
else if (version == '12.2(2)XB6')
  security_hole(0);
else if (version == '12.2(2)XB5')
  security_hole(0);
else if (version == '12.2(2)XB3')
  security_hole(0);
else if (version == '12.2(2)XB2')
  security_hole(0);
else if (version == '12.2(2)XB15')
  security_hole(0);
else if (version == '12.2(2)XB14')
  security_hole(0);
else if (version == '12.2(2)XB12')
  security_hole(0);
else if (version == '12.2(2)XB11')
  security_hole(0);
else if (version == '12.2(2)XB10')
  security_hole(0);
else if (version == '12.2(2)XB1')
  security_hole(0);
else if (version == '12.2(2)XA5')
  security_hole(0);
else if (version == '12.2(2)XA4')
  security_hole(0);
else if (version == '12.2(2)XA3')
  security_hole(0);
else if (version == '12.2(2)XA2')
  security_hole(0);
else if (version == '12.2(2)XA1')
  security_hole(0);
else if (version == '12.2(2)XA')
  security_hole(0);
else if (version == '12.2(8)TPC10c')
  security_hole(0);
else if (version == '12.2(8)TPC10b')
  security_hole(0);
else if (version == '12.2(8)TPC10a')
  security_hole(0);
else if (version == '12.2(15)T9')
  security_hole(0);
else if (version == '12.2(15)T8')
  security_hole(0);
else if (version == '12.2(15)T7')
  security_hole(0);
else if (version == '12.2(15)T5')
  security_hole(0);
else if (version == '12.2(15)T4e')
  security_hole(0);
else if (version == '12.2(15)T4')
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
else if (version == '12.2(13)T2')
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
else if (version == '12.2(11)T4')
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
else if (version == '12.2(8)T8')
  security_hole(0);
else if (version == '12.2(8)T7')
  security_hole(0);
else if (version == '12.2(8)T5')
  security_hole(0);
else if (version == '12.2(8)T4')
  security_hole(0);
else if (version == '12.2(8)T3')
  security_hole(0);
else if (version == '12.2(8)T2')
  security_hole(0);
else if (version == '12.2(8)T10')
  security_hole(0);
else if (version == '12.2(8)T1')
  security_hole(0);
else if (version == '12.2(8)T')
  security_hole(0);
else if (version == '12.2(4)T7')
  security_hole(0);
else if (version == '12.2(4)T6')
  security_hole(0);
else if (version == '12.2(4)T5')
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
else if (version == '12.2(2)T3')
  security_hole(0);
else if (version == '12.2(2)T2')
  security_hole(0);
else if (version == '12.2(2)T1')
  security_hole(0);
else if (version == '12.2(2)T')
  security_hole(0);
else if (version == '12.2(14)SZ6')
  security_hole(0);
else if (version == '12.2(14)SZ5')
  security_hole(0);
else if (version == '12.2(14)SZ4')
  security_hole(0);
else if (version == '12.2(14)SZ3')
  security_hole(0);
else if (version == '12.2(14)SZ2')
  security_hole(0);
else if (version == '12.2(14)SZ1')
  security_hole(0);
else if (version == '12.2(14)SZ')
  security_hole(0);
else if (version == '12.2(14)SY5')
  security_hole(0);
else if (version == '12.2(14)SY4')
  security_hole(0);
else if (version == '12.2(14)SY3')
  security_hole(0);
else if (version == '12.2(14)SY2')
  security_hole(0);
else if (version == '12.2(14)SY1')
  security_hole(0);
else if (version == '12.2(14)SY')
  security_hole(0);
else if (version == '12.2(33)SXI')
  security_hole(0);
else if (version == '12.2(33)SXH4')
  security_hole(0);
else if (version == '12.2(33)SXH3a')
  security_hole(0);
else if (version == '12.2(33)SXH3')
  security_hole(0);
else if (version == '12.2(33)SXH2a')
  security_hole(0);
else if (version == '12.2(33)SXH2')
  security_hole(0);
else if (version == '12.2(33)SXH1')
  security_hole(0);
else if (version == '12.2(33)SXH')
  security_hole(0);
else if (version == '12.2(18)SXF9')
  security_hole(0);
else if (version == '12.2(18)SXF8')
  security_hole(0);
else if (version == '12.2(18)SXF7')
  security_hole(0);
else if (version == '12.2(18)SXF6')
  security_hole(0);
else if (version == '12.2(18)SXF5')
  security_hole(0);
else if (version == '12.2(18)SXF4')
  security_hole(0);
else if (version == '12.2(18)SXF3')
  security_hole(0);
else if (version == '12.2(18)SXF2')
  security_hole(0);
else if (version == '12.2(18)SXF15a')
  security_hole(0);
else if (version == '12.2(18)SXF15')
  security_hole(0);
else if (version == '12.2(18)SXF14')
  security_hole(0);
else if (version == '12.2(18)SXF13')
  security_hole(0);
else if (version == '12.2(18)SXF12a')
  security_hole(0);
else if (version == '12.2(18)SXF12')
  security_hole(0);
else if (version == '12.2(18)SXF11')
  security_hole(0);
else if (version == '12.2(18)SXF10a')
  security_hole(0);
else if (version == '12.2(18)SXF10')
  security_hole(0);
else if (version == '12.2(18)SXF1')
  security_hole(0);
else if (version == '12.2(18)SXF')
  security_hole(0);
else if (version == '12.2(18)SXE6b')
  security_hole(0);
else if (version == '12.2(18)SXE6a')
  security_hole(0);
else if (version == '12.2(18)SXE6')
  security_hole(0);
else if (version == '12.2(18)SXE5')
  security_hole(0);
else if (version == '12.2(18)SXE4')
  security_hole(0);
else if (version == '12.2(18)SXE3')
  security_hole(0);
else if (version == '12.2(18)SXE2')
  security_hole(0);
else if (version == '12.2(18)SXE1')
  security_hole(0);
else if (version == '12.2(18)SXE')
  security_hole(0);
else if (version == '12.2(18)SXD7b')
  security_hole(0);
else if (version == '12.2(18)SXD7a')
  security_hole(0);
else if (version == '12.2(18)SXD7')
  security_hole(0);
else if (version == '12.2(18)SXD6')
  security_hole(0);
else if (version == '12.2(18)SXD5')
  security_hole(0);
else if (version == '12.2(18)SXD4')
  security_hole(0);
else if (version == '12.2(18)SXD3')
  security_hole(0);
else if (version == '12.2(18)SXD2')
  security_hole(0);
else if (version == '12.2(18)SXD1')
  security_hole(0);
else if (version == '12.2(18)SXD')
  security_hole(0);
else if (version == '12.2(17d)SXB9')
  security_hole(0);
else if (version == '12.2(17d)SXB8')
  security_hole(0);
else if (version == '12.2(17d)SXB7')
  security_hole(0);
else if (version == '12.2(17d)SXB6')
  security_hole(0);
else if (version == '12.2(17d)SXB5')
  security_hole(0);
else if (version == '12.2(17d)SXB4')
  security_hole(0);
else if (version == '12.2(17d)SXB3')
  security_hole(0);
else if (version == '12.2(17d)SXB2')
  security_hole(0);
else if (version == '12.2(17d)SXB11a')
  security_hole(0);
else if (version == '12.2(17d)SXB11')
  security_hole(0);
else if (version == '12.2(17d)SXB10')
  security_hole(0);
else if (version == '12.2(17d)SXB1')
  security_hole(0);
else if (version == '12.2(17d)SXB')
  security_hole(0);
else if (version == '12.2(17b)SXA2')
  security_hole(0);
else if (version == '12.2(17b)SXA')
  security_hole(0);
else if (version == '12.2(17a)SX4')
  security_hole(0);
else if (version == '12.2(17a)SX3')
  security_hole(0);
else if (version == '12.2(17a)SX2')
  security_hole(0);
else if (version == '12.2(17a)SX1')
  security_hole(0);
else if (version == '12.2(17a)SX')
  security_hole(0);
else if (version == '12.2(14)SX2')
  security_hole(0);
else if (version == '12.2(14)SX1')
  security_hole(0);
else if (version == '12.2(14)SX')
  security_hole(0);
else if (version == '12.2(25)SW9')
  security_hole(0);
else if (version == '12.2(25)SW8')
  security_hole(0);
else if (version == '12.2(25)SW7')
  security_hole(0);
else if (version == '12.2(25)SW6')
  security_hole(0);
else if (version == '12.2(25)SW5')
  security_hole(0);
else if (version == '12.2(25)SW4a')
  security_hole(0);
else if (version == '12.2(25)SW4')
  security_hole(0);
else if (version == '12.2(25)SW3a')
  security_hole(0);
else if (version == '12.2(25)SW3')
  security_hole(0);
else if (version == '12.2(25)SW2')
  security_hole(0);
else if (version == '12.2(25)SW12')
  security_hole(0);
else if (version == '12.2(25)SW11')
  security_hole(0);
else if (version == '12.2(25)SW10')
  security_hole(0);
else if (version == '12.2(25)SW1')
  security_hole(0);
else if (version == '12.2(23)SW1')
  security_hole(0);
else if (version == '12.2(23)SW')
  security_hole(0);
else if (version == '12.2(21)SW1')
  security_hole(0);
else if (version == '12.2(21)SW')
  security_hole(0);
else if (version == '12.2(20)SW')
  security_hole(0);
else if (version == '12.2(19)SW')
  security_hole(0);
else if (version == '12.2(18)SW')
  security_hole(0);
else if (version == '12.2(29)SVE0')
  security_hole(0);
else if (version == '12.2(29)SVD1')
  security_hole(0);
else if (version == '12.2(29)SVD0')
  security_hole(0);
else if (version == '12.2(29)SVD')
  security_hole(0);
else if (version == '12.2(29)SVC')
  security_hole(0);
else if (version == '12.2(29)SVA2')
  security_hole(0);
else if (version == '12.2(29b)SV1')
  security_hole(0);
else if (version == '12.2(29b)SV')
  security_hole(0);
else if (version == '12.2(29a)SV1')
  security_hole(0);
else if (version == '12.2(29a)SV')
  security_hole(0);
else if (version == '12.2(29)SV3')
  security_hole(0);
else if (version == '12.2(29)SV2')
  security_hole(0);
else if (version == '12.2(29)SV1')
  security_hole(0);
else if (version == '12.2(29)SV')
  security_hole(0);
else if (version == '12.2(28)SV2')
  security_hole(0);
else if (version == '12.2(28)SV1')
  security_hole(0);
else if (version == '12.2(28)SV')
  security_hole(0);
else if (version == '12.2(27)SV5')
  security_hole(0);
else if (version == '12.2(27)SV4')
  security_hole(0);
else if (version == '12.2(27)SV3')
  security_hole(0);
else if (version == '12.2(27)SV2')
  security_hole(0);
else if (version == '12.2(27)SV1')
  security_hole(0);
else if (version == '12.2(27)SV')
  security_hole(0);
else if (version == '12.2(26)SV1')
  security_hole(0);
else if (version == '12.2(26)SV')
  security_hole(0);
else if (version == '12.2(25)SV3')
  security_hole(0);
else if (version == '12.2(25)SV2')
  security_hole(0);
else if (version == '12.2(25)SV')
  security_hole(0);
else if (version == '12.2(24)SV1')
  security_hole(0);
else if (version == '12.2(24)SV')
  security_hole(0);
else if (version == '12.2(23)SV1')
  security_hole(0);
else if (version == '12.2(23)SV')
  security_hole(0);
else if (version == '12.2(22)SV1')
  security_hole(0);
else if (version == '12.2(22)SV')
  security_hole(0);
else if (version == '12.2(18)SV3')
  security_hole(0);
else if (version == '12.2(18)SV2')
  security_hole(0);
else if (version == '12.2(18)SV1')
  security_hole(0);
else if (version == '12.2(18)SV')
  security_hole(0);
else if (version == '12.2(14)SU2')
  security_hole(0);
else if (version == '12.2(14)SU1')
  security_hole(0);
else if (version == '12.2(14)SU')
  security_hole(0);
else if (version == '12.2(33)STE0')
  security_hole(0);
else if (version == '12.2(33)SRD')
  security_hole(0);
else if (version == '12.2(33)SRC2')
  security_hole(0);
else if (version == '12.2(33)SRC1')
  security_hole(0);
else if (version == '12.2(33)SRC')
  security_hole(0);
else if (version == '12.2(33)SRB5')
  security_hole(0);
else if (version == '12.2(33)SRB4')
  security_hole(0);
else if (version == '12.2(33)SRB3')
  security_hole(0);
else if (version == '12.2(33)SRB2')
  security_hole(0);
else if (version == '12.2(33)SRB1')
  security_hole(0);
else if (version == '12.2(33)SRB')
  security_hole(0);
else if (version == '12.2(33)SRA7')
  security_hole(0);
else if (version == '12.2(33)SRA6')
  security_hole(0);
else if (version == '12.2(33)SRA5')
  security_hole(0);
else if (version == '12.2(33)SRA4')
  security_hole(0);
else if (version == '12.2(33)SRA3')
  security_hole(0);
else if (version == '12.2(33)SRA2')
  security_hole(0);
else if (version == '12.2(33)SRA1')
  security_hole(0);
else if (version == '12.2(33)SRA')
  security_hole(0);
else if (version == '12.2(44)SQ')
  security_hole(0);
else if (version == '12.2(18)SO7')
  security_hole(0);
else if (version == '12.2(18)SO6')
  security_hole(0);
else if (version == '12.2(18)SO5')
  security_hole(0);
else if (version == '12.2(18)SO4')
  security_hole(0);
else if (version == '12.2(18)SO3')
  security_hole(0);
else if (version == '12.2(18)SO2')
  security_hole(0);
else if (version == '12.2(18)SO1')
  security_hole(0);
else if (version == '12.2(29)SM4')
  security_hole(0);
else if (version == '12.2(29)SM3')
  security_hole(0);
else if (version == '12.2(29)SM2')
  security_hole(0);
else if (version == '12.2(29)SM1')
  security_hole(0);
else if (version == '12.2(29)SM')
  security_hole(0);
else if (version == '12.2(31)SGA8')
  security_hole(0);
else if (version == '12.2(31)SGA7')
  security_hole(0);
else if (version == '12.2(31)SGA6')
  security_hole(0);
else if (version == '12.2(31)SGA5')
  security_hole(0);
else if (version == '12.2(31)SGA4')
  security_hole(0);
else if (version == '12.2(31)SGA3')
  security_hole(0);
else if (version == '12.2(31)SGA2')
  security_hole(0);
else if (version == '12.2(31)SGA1')
  security_hole(0);
else if (version == '12.2(31)SGA')
  security_hole(0);
else if (version == '12.2(46)SG1')
  security_hole(0);
else if (version == '12.2(46)SG')
  security_hole(0);
else if (version == '12.2(44)SG1')
  security_hole(0);
else if (version == '12.2(44)SG')
  security_hole(0);
else if (version == '12.2(40)SG')
  security_hole(0);
else if (version == '12.2(37)SG1')
  security_hole(0);
else if (version == '12.2(37)SG')
  security_hole(0);
else if (version == '12.2(31)SG3')
  security_hole(0);
else if (version == '12.2(31)SG2')
  security_hole(0);
else if (version == '12.2(31)SG1')
  security_hole(0);
else if (version == '12.2(31)SG')
  security_hole(0);
else if (version == '12.2(25)SG4')
  security_hole(0);
else if (version == '12.2(25)SG3')
  security_hole(0);
else if (version == '12.2(25)SG2')
  security_hole(0);
else if (version == '12.2(25)SG1')
  security_hole(0);
else if (version == '12.2(25)SG')
  security_hole(0);
else if (version == '12.2(25)SEG6')
  security_hole(0);
else if (version == '12.2(25)SEG5')
  security_hole(0);
else if (version == '12.2(25)SEG4')
  security_hole(0);
else if (version == '12.2(25)SEG3')
  security_hole(0);
else if (version == '12.2(25)SEG2')
  security_hole(0);
else if (version == '12.2(25)SEG1')
  security_hole(0);
else if (version == '12.2(25)SEG')
  security_hole(0);
else if (version == '12.2(25)SEF3')
  security_hole(0);
else if (version == '12.2(25)SEF2')
  security_hole(0);
else if (version == '12.2(25)SEF1')
  security_hole(0);
else if (version == '12.2(25)SEE4')
  security_hole(0);
else if (version == '12.2(25)SEE3')
  security_hole(0);
else if (version == '12.2(25)SEE2')
  security_hole(0);
else if (version == '12.2(25)SEE1')
  security_hole(0);
else if (version == '12.2(25)SEE')
  security_hole(0);
else if (version == '12.2(25)SED1')
  security_hole(0);
else if (version == '12.2(25)SED')
  security_hole(0);
else if (version == '12.2(25)SEC2')
  security_hole(0);
else if (version == '12.2(25)SEC1')
  security_hole(0);
else if (version == '12.2(25)SEC')
  security_hole(0);
else if (version == '12.2(25)SEB4')
  security_hole(0);
else if (version == '12.2(25)SEB3')
  security_hole(0);
else if (version == '12.2(25)SEB2')
  security_hole(0);
else if (version == '12.2(25)SEB1')
  security_hole(0);
else if (version == '12.2(25)SEB')
  security_hole(0);
else if (version == '12.2(25)SEA')
  security_hole(0);
else if (version == '12.2(46)SE1')
  security_hole(0);
else if (version == '12.2(46)SE')
  security_hole(0);
else if (version == '12.2(44)SE4')
  security_hole(0);
else if (version == '12.2(44)SE3')
  security_hole(0);
else if (version == '12.2(44)SE2')
  security_hole(0);
else if (version == '12.2(44)SE1')
  security_hole(0);
else if (version == '12.2(44)SE')
  security_hole(0);
else if (version == '12.2(40)SE2')
  security_hole(0);
else if (version == '12.2(40)SE1')
  security_hole(0);
else if (version == '12.2(40)SE')
  security_hole(0);
else if (version == '12.2(37)SE1')
  security_hole(0);
else if (version == '12.2(37)SE')
  security_hole(0);
else if (version == '12.2(35)SE5')
  security_hole(0);
else if (version == '12.2(35)SE4')
  security_hole(0);
else if (version == '12.2(35)SE3')
  security_hole(0);
else if (version == '12.2(35)SE2')
  security_hole(0);
else if (version == '12.2(35)SE1')
  security_hole(0);
else if (version == '12.2(35)SE')
  security_hole(0);
else if (version == '12.2(25)SE3')
  security_hole(0);
else if (version == '12.2(25)SE2')
  security_hole(0);
else if (version == '12.2(25)SE')
  security_hole(0);
else if (version == '12.2(20)SE4')
  security_hole(0);
else if (version == '12.2(20)SE3')
  security_hole(0);
else if (version == '12.2(20)SE2')
  security_hole(0);
else if (version == '12.2(20)SE1')
  security_hole(0);
else if (version == '12.2(20)SE')
  security_hole(0);
else if (version == '12.2(18)SE1')
  security_hole(0);
else if (version == '12.2(18)SE')
  security_hole(0);
else if (version == '12.2(33)SCB')
  security_hole(0);
else if (version == '12.2(33)SCA2')
  security_hole(0);
else if (version == '12.2(33)SCA1')
  security_hole(0);
else if (version == '12.2(33)SCA')
  security_hole(0);
else if (version == '12.2(27)SBC5')
  security_hole(0);
else if (version == '12.2(27)SBC4')
  security_hole(0);
else if (version == '12.2(27)SBC3')
  security_hole(0);
else if (version == '12.2(27)SBC2')
  security_hole(0);
else if (version == '12.2(27)SBC1')
  security_hole(0);
else if (version == '12.2(27)SBC')
  security_hole(0);
else if (version == '12.2(27)SBB4e')
  security_hole(0);
else if (version == '12.2(33)SB2')
  security_hole(0);
else if (version == '12.2(33)SB1')
  security_hole(0);
else if (version == '12.2(33)SB')
  security_hole(0);
else if (version == '12.2(31)SB9')
  security_hole(0);
else if (version == '12.2(31)SB8')
  security_hole(0);
else if (version == '12.2(31)SB7')
  security_hole(0);
else if (version == '12.2(31)SB6')
  security_hole(0);
else if (version == '12.2(31)SB5')
  security_hole(0);
else if (version == '12.2(31)SB3x')
  security_hole(0);
else if (version == '12.2(31)SB3')
  security_hole(0);
else if (version == '12.2(31)SB2')
  security_hole(0);
else if (version == '12.2(31)SB13')
  security_hole(0);
else if (version == '12.2(31)SB12')
  security_hole(0);
else if (version == '12.2(31)SB11')
  security_hole(0);
else if (version == '12.2(31)SB10')
  security_hole(0);
else if (version == '12.2(28)SB9')
  security_hole(0);
else if (version == '12.2(28)SB8')
  security_hole(0);
else if (version == '12.2(28)SB7')
  security_hole(0);
else if (version == '12.2(28)SB6')
  security_hole(0);
else if (version == '12.2(28)SB5c')
  security_hole(0);
else if (version == '12.2(28)SB5')
  security_hole(0);
else if (version == '12.2(28)SB4d')
  security_hole(0);
else if (version == '12.2(28)SB4')
  security_hole(0);
else if (version == '12.2(28)SB3')
  security_hole(0);
else if (version == '12.2(28)SB2')
  security_hole(0);
else if (version == '12.2(28)SB12')
  security_hole(0);
else if (version == '12.2(28)SB11')
  security_hole(0);
else if (version == '12.2(28)SB10')
  security_hole(0);
else if (version == '12.2(28)SB1')
  security_hole(0);
else if (version == '12.2(28)SB')
  security_hole(0);
else if (version == '12.2(30)S1')
  security_hole(0);
else if (version == '12.2(30)S')
  security_hole(0);
else if (version == '12.2(25)S9')
  security_hole(0);
else if (version == '12.2(25)S8')
  security_hole(0);
else if (version == '12.2(25)S7')
  security_hole(0);
else if (version == '12.2(25)S6')
  security_hole(0);
else if (version == '12.2(25)S5')
  security_hole(0);
else if (version == '12.2(25)S4')
  security_hole(0);
else if (version == '12.2(25)S3')
  security_hole(0);
else if (version == '12.2(25)S2')
  security_hole(0);
else if (version == '12.2(25)S15')
  security_hole(0);
else if (version == '12.2(25)S14')
  security_hole(0);
else if (version == '12.2(25)S13')
  security_hole(0);
else if (version == '12.2(25)S12')
  security_hole(0);
else if (version == '12.2(25)S11')
  security_hole(0);
else if (version == '12.2(25)S10')
  security_hole(0);
else if (version == '12.2(25)S1')
  security_hole(0);
else if (version == '12.2(25)S')
  security_hole(0);
else if (version == '12.2(22)S2')
  security_hole(0);
else if (version == '12.2(22)S1')
  security_hole(0);
else if (version == '12.2(22)S')
  security_hole(0);
else if (version == '12.2(20)S9')
  security_hole(0);
else if (version == '12.2(20)S8')
  security_hole(0);
else if (version == '12.2(20)S7')
  security_hole(0);
else if (version == '12.2(20)S6')
  security_hole(0);
else if (version == '12.2(20)S5')
  security_hole(0);
else if (version == '12.2(20)S4')
  security_hole(0);
else if (version == '12.2(20)S3')
  security_hole(0);
else if (version == '12.2(20)S2')
  security_hole(0);
else if (version == '12.2(20)S14')
  security_hole(0);
else if (version == '12.2(20)S13')
  security_hole(0);
else if (version == '12.2(20)S12')
  security_hole(0);
else if (version == '12.2(20)S11')
  security_hole(0);
else if (version == '12.2(20)S10')
  security_hole(0);
else if (version == '12.2(20)S1')
  security_hole(0);
else if (version == '12.2(20)S')
  security_hole(0);
else if (version == '12.2(18)S9')
  security_hole(0);
else if (version == '12.2(18)S8')
  security_hole(0);
else if (version == '12.2(18)S7')
  security_hole(0);
else if (version == '12.2(18)S6')
  security_hole(0);
else if (version == '12.2(18)S5')
  security_hole(0);
else if (version == '12.2(18)S4')
  security_hole(0);
else if (version == '12.2(18)S3')
  security_hole(0);
else if (version == '12.2(18)S2')
  security_hole(0);
else if (version == '12.2(18)S13')
  security_hole(0);
else if (version == '12.2(18)S12')
  security_hole(0);
else if (version == '12.2(18)S11')
  security_hole(0);
else if (version == '12.2(18)S10')
  security_hole(0);
else if (version == '12.2(18)S1')
  security_hole(0);
else if (version == '12.2(18)S')
  security_hole(0);
else if (version == '12.2(14)S9')
  security_hole(0);
else if (version == '12.2(14)S8')
  security_hole(0);
else if (version == '12.2(14)S7')
  security_hole(0);
else if (version == '12.2(14)S5')
  security_hole(0);
else if (version == '12.2(14)S3')
  security_hole(0);
else if (version == '12.2(14)S2')
  security_hole(0);
else if (version == '12.2(14)S19')
  security_hole(0);
else if (version == '12.2(14)S18')
  security_hole(0);
else if (version == '12.2(14)S17')
  security_hole(0);
else if (version == '12.2(14)S16')
  security_hole(0);
else if (version == '12.2(14)S15')
  security_hole(0);
else if (version == '12.2(14)S14')
  security_hole(0);
else if (version == '12.2(14)S13')
  security_hole(0);
else if (version == '12.2(14)S12')
  security_hole(0);
else if (version == '12.2(14)S11')
  security_hole(0);
else if (version == '12.2(14)S10')
  security_hole(0);
else if (version == '12.2(14)S1')
  security_hole(0);
else if (version == '12.2(14)S')
  security_hole(0);
else if (version == '12.2(9)S')
  security_hole(0);
else if (version == '12.2(15)MC2l')
  security_hole(0);
else if (version == '12.2(15)MC2k')
  security_hole(0);
else if (version == '12.2(15)MC2j')
  security_hole(0);
else if (version == '12.2(15)MC2i')
  security_hole(0);
else if (version == '12.2(15)MC2h')
  security_hole(0);
else if (version == '12.2(15)MC2g')
  security_hole(0);
else if (version == '12.2(15)MC2f')
  security_hole(0);
else if (version == '12.2(15)MC2e')
  security_hole(0);
else if (version == '12.2(15)MC2c')
  security_hole(0);
else if (version == '12.2(15)MC2b')
  security_hole(0);
else if (version == '12.2(15)MC2a')
  security_hole(0);
else if (version == '12.2(15)MC2')
  security_hole(0);
else if (version == '12.2(15)MC1c')
  security_hole(0);
else if (version == '12.2(15)MC1b')
  security_hole(0);
else if (version == '12.2(15)MC1a')
  security_hole(0);
else if (version == '12.2(15)MC1')
  security_hole(0);
else if (version == '12.2(8)MC2d')
  security_hole(0);
else if (version == '12.2(8)MC2c')
  security_hole(0);
else if (version == '12.2(8)MC2b')
  security_hole(0);
else if (version == '12.2(8)MC2a')
  security_hole(0);
else if (version == '12.2(8)MC2')
  security_hole(0);
else if (version == '12.2(8)MC1')
  security_hole(0);
else if (version == '12.2(4)MB9a')
  security_hole(0);
else if (version == '12.2(4)MB9')
  security_hole(0);
else if (version == '12.2(4)MB8')
  security_hole(0);
else if (version == '12.2(4)MB7')
  security_hole(0);
else if (version == '12.2(4)MB6')
  security_hole(0);
else if (version == '12.2(4)MB5')
  security_hole(0);
else if (version == '12.2(4)MB4')
  security_hole(0);
else if (version == '12.2(4)MB3')
  security_hole(0);
else if (version == '12.2(4)MB2')
  security_hole(0);
else if (version == '12.2(4)MB13c')
  security_hole(0);
else if (version == '12.2(4)MB13b')
  security_hole(0);
else if (version == '12.2(4)MB13a')
  security_hole(0);
else if (version == '12.2(4)MB13')
  security_hole(0);
else if (version == '12.2(4)MB12')
  security_hole(0);
else if (version == '12.2(4)MB11')
  security_hole(0);
else if (version == '12.2(4)MB10')
  security_hole(0);
else if (version == '12.2(4)MB1')
  security_hole(0);
else if (version == '12.2(1)MB1')
  security_hole(0);
else if (version == '12.2(12h)M1')
  security_hole(0);
else if (version == '12.2(12b)M1')
  security_hole(0);
else if (version == '12.2(6c)M1')
  security_hole(0);
else if (version == '12.2(1)M0')
  security_hole(0);
else if (version == '12.2(15)JK5')
  security_hole(0);
else if (version == '12.2(15)JK4')
  security_hole(0);
else if (version == '12.2(15)JK3')
  security_hole(0);
else if (version == '12.2(15)JK2')
  security_hole(0);
else if (version == '12.2(15)JK1')
  security_hole(0);
else if (version == '12.2(15)JK')
  security_hole(0);
else if (version == '12.2(15)JA')
  security_hole(0);
else if (version == '12.2(13)JA4')
  security_hole(0);
else if (version == '12.2(13)JA3')
  security_hole(0);
else if (version == '12.2(13)JA2')
  security_hole(0);
else if (version == '12.2(13)JA1')
  security_hole(0);
else if (version == '12.2(13)JA')
  security_hole(0);
else if (version == '12.2(11)JA3')
  security_hole(0);
else if (version == '12.2(11)JA2')
  security_hole(0);
else if (version == '12.2(11)JA1')
  security_hole(0);
else if (version == '12.2(11)JA')
  security_hole(0);
else if (version == '12.2(8)JA')
  security_hole(0);
else if (version == '12.2(4)JA1')
  security_hole(0);
else if (version == '12.2(4)JA')
  security_hole(0);
else if (version == '12.2(18)IXG')
  security_hole(0);
else if (version == '12.2(18)IXF1')
  security_hole(0);
else if (version == '12.2(18)IXF')
  security_hole(0);
else if (version == '12.2(18)IXE')
  security_hole(0);
else if (version == '12.2(18)IXD1')
  security_hole(0);
else if (version == '12.2(18)IXD')
  security_hole(0);
else if (version == '12.2(18)IXC')
  security_hole(0);
else if (version == '12.2(18)IXB2')
  security_hole(0);
else if (version == '12.2(18)IXB1')
  security_hole(0);
else if (version == '12.2(18)IXB')
  security_hole(0);
else if (version == '12.2(18)IXA')
  security_hole(0);
else if (version == '12.2(33)IRB')
  security_hole(0);
else if (version == '12.2(33)IRA')
  security_hole(0);
else if (version == '12.2(25)FZ')
  security_hole(0);
else if (version == '12.2(25)FY')
  security_hole(0);
else if (version == '12.2(25)FX')
  security_hole(0);
else if (version == '12.2(25)EZ1')
  security_hole(0);
else if (version == '12.2(25)EZ')
  security_hole(0);
else if (version == '12.2(37)EY')
  security_hole(0);
else if (version == '12.2(25)EY4')
  security_hole(0);
else if (version == '12.2(25)EY3')
  security_hole(0);
else if (version == '12.2(25)EY2')
  security_hole(0);
else if (version == '12.2(25)EY1')
  security_hole(0);
else if (version == '12.2(25)EY')
  security_hole(0);
else if (version == '12.2(46)EX')
  security_hole(0);
else if (version == '12.2(44)EX1')
  security_hole(0);
else if (version == '12.2(44)EX')
  security_hole(0);
else if (version == '12.2(40)EX3')
  security_hole(0);
else if (version == '12.2(40)EX2')
  security_hole(0);
else if (version == '12.2(40)EX1')
  security_hole(0);
else if (version == '12.2(40)EX')
  security_hole(0);
else if (version == '12.2(37)EX')
  security_hole(0);
else if (version == '12.2(35)EX2')
  security_hole(0);
else if (version == '12.2(35)EX1')
  security_hole(0);
else if (version == '12.2(35)EX')
  security_hole(0);
else if (version == '12.2(25)EX1')
  security_hole(0);
else if (version == '12.2(25)EX')
  security_hole(0);
else if (version == '12.2(20)EX')
  security_hole(0);
else if (version == '12.2(25)EWA9')
  security_hole(0);
else if (version == '12.2(25)EWA8')
  security_hole(0);
else if (version == '12.2(25)EWA7')
  security_hole(0);
else if (version == '12.2(25)EWA6')
  security_hole(0);
else if (version == '12.2(25)EWA5')
  security_hole(0);
else if (version == '12.2(25)EWA4')
  security_hole(0);
else if (version == '12.2(25)EWA3')
  security_hole(0);
else if (version == '12.2(25)EWA2')
  security_hole(0);
else if (version == '12.2(25)EWA14')
  security_hole(0);
else if (version == '12.2(25)EWA13')
  security_hole(0);
else if (version == '12.2(25)EWA12')
  security_hole(0);
else if (version == '12.2(25)EWA11')
  security_hole(0);
else if (version == '12.2(25)EWA10')
  security_hole(0);
else if (version == '12.2(25)EWA1')
  security_hole(0);
else if (version == '12.2(25)EWA')
  security_hole(0);
else if (version == '12.2(20)EWA4')
  security_hole(0);
else if (version == '12.2(20)EWA3')
  security_hole(0);
else if (version == '12.2(20)EWA2')
  security_hole(0);
else if (version == '12.2(20)EWA1')
  security_hole(0);
else if (version == '12.2(20)EWA')
  security_hole(0);
else if (version == '12.2(25)EW')
  security_hole(0);
else if (version == '12.2(20)EW4')
  security_hole(0);
else if (version == '12.2(20)EW3')
  security_hole(0);
else if (version == '12.2(20)EW2')
  security_hole(0);
else if (version == '12.2(20)EW1')
  security_hole(0);
else if (version == '12.2(20)EW')
  security_hole(0);
else if (version == '12.2(18)EW7')
  security_hole(0);
else if (version == '12.2(18)EW6')
  security_hole(0);
else if (version == '12.2(18)EW5')
  security_hole(0);
else if (version == '12.2(18)EW4')
  security_hole(0);
else if (version == '12.2(18)EW3')
  security_hole(0);
else if (version == '12.2(18)EW2')
  security_hole(0);
else if (version == '12.2(18)EW1')
  security_hole(0);
else if (version == '12.2(18)EW')
  security_hole(0);
else if (version == '12.2(20)EU2')
  security_hole(0);
else if (version == '12.2(20)EU1')
  security_hole(0);
else if (version == '12.2(20)EU')
  security_hole(0);
else if (version == '12.2(2)DX3')
  security_hole(0);
else if (version == '12.2(1)DX1')
  security_hole(0);
else if (version == '12.2(1)DX')
  security_hole(0);
else if (version == '12.2(2)DD4')
  security_hole(0);
else if (version == '12.2(2)DD3')
  security_hole(0);
else if (version == '12.2(2)DD2')
  security_hole(0);
else if (version == '12.2(2)DD1')
  security_hole(0);
else if (version == '12.2(2)DD')
  security_hole(0);
else if (version == '12.2(12)DA9')
  security_hole(0);
else if (version == '12.2(12)DA8')
  security_hole(0);
else if (version == '12.2(12)DA7')
  security_hole(0);
else if (version == '12.2(12)DA6')
  security_hole(0);
else if (version == '12.2(12)DA5')
  security_hole(0);
else if (version == '12.2(12)DA4')
  security_hole(0);
else if (version == '12.2(12)DA3')
  security_hole(0);
else if (version == '12.2(12)DA2')
  security_hole(0);
else if (version == '12.2(12)DA13')
  security_hole(0);
else if (version == '12.2(12)DA12')
  security_hole(0);
else if (version == '12.2(12)DA11')
  security_hole(0);
else if (version == '12.2(12)DA10')
  security_hole(0);
else if (version == '12.2(12)DA1')
  security_hole(0);
else if (version == '12.2(12)DA')
  security_hole(0);
else if (version == '12.2(10)DA9')
  security_hole(0);
else if (version == '12.2(10)DA8')
  security_hole(0);
else if (version == '12.2(10)DA7')
  security_hole(0);
else if (version == '12.2(10)DA6')
  security_hole(0);
else if (version == '12.2(10)DA5')
  security_hole(0);
else if (version == '12.2(10)DA4')
  security_hole(0);
else if (version == '12.2(10)DA3')
  security_hole(0);
else if (version == '12.2(10)DA2')
  security_hole(0);
else if (version == '12.2(10)DA1')
  security_hole(0);
else if (version == '12.2(10)DA')
  security_hole(0);
else if (version == '12.2(7)DA')
  security_hole(0);
else if (version == '12.2(5)DA1')
  security_hole(0);
else if (version == '12.2(5)DA')
  security_hole(0);
else if (version == '12.2(1b)DA1')
  security_hole(0);
else if (version == '12.2(1b)DA')
  security_hole(0);
else if (version == '12.2(15)CZ3')
  security_hole(0);
else if (version == '12.2(15)CZ2')
  security_hole(0);
else if (version == '12.2(15)CZ1')
  security_hole(0);
else if (version == '12.2(15)CZ')
  security_hole(0);
else if (version == '12.2(11)CY')
  security_hole(0);
else if (version == '12.2(15)CX1')
  security_hole(0);
else if (version == '12.2(15)CX')
  security_hole(0);
else if (version == '12.2(11)CX1')
  security_hole(0);
else if (version == '12.2(11)CX')
  security_hole(0);
else if (version == '12.2(15)BZ2')
  security_hole(0);
else if (version == '12.2(4)BZ2')
  security_hole(0);
else if (version == '12.2(4)BZ1')
  security_hole(0);
else if (version == '12.2(8)BY2')
  security_hole(0);
else if (version == '12.2(8)BY1')
  security_hole(0);
else if (version == '12.2(8)BY')
  security_hole(0);
else if (version == '12.2(2)BY3')
  security_hole(0);
else if (version == '12.2(2)BY2')
  security_hole(0);
else if (version == '12.2(2)BY1')
  security_hole(0);
else if (version == '12.2(2)BY')
  security_hole(0);
else if (version == '12.2(16)BX3')
  security_hole(0);
else if (version == '12.2(16)BX2')
  security_hole(0);
else if (version == '12.2(16)BX1')
  security_hole(0);
else if (version == '12.2(16)BX')
  security_hole(0);
else if (version == '12.2(15)BX')
  security_hole(0);
else if (version == '12.2(2)BX1')
  security_hole(0);
else if (version == '12.2(2)BX')
  security_hole(0);
else if (version == '12.2(4)BW2')
  security_hole(0);
else if (version == '12.2(4)BW1a')
  security_hole(0);
else if (version == '12.2(4)BW1')
  security_hole(0);
else if (version == '12.2(4)BW')
  security_hole(0);
else if (version == '12.2(15)BC2i')
  security_hole(0);
else if (version == '12.2(15)BC2h')
  security_hole(0);
else if (version == '12.2(15)BC2g')
  security_hole(0);
else if (version == '12.2(15)BC2f')
  security_hole(0);
else if (version == '12.2(15)BC2e')
  security_hole(0);
else if (version == '12.2(15)BC2d')
  security_hole(0);
else if (version == '12.2(15)BC2c')
  security_hole(0);
else if (version == '12.2(15)BC2b')
  security_hole(0);
else if (version == '12.2(15)BC2a')
  security_hole(0);
else if (version == '12.2(15)BC2')
  security_hole(0);
else if (version == '12.2(15)BC1g')
  security_hole(0);
else if (version == '12.2(15)BC1f')
  security_hole(0);
else if (version == '12.2(15)BC1e')
  security_hole(0);
else if (version == '12.2(15)BC1d')
  security_hole(0);
else if (version == '12.2(15)BC1c')
  security_hole(0);
else if (version == '12.2(15)BC1b')
  security_hole(0);
else if (version == '12.2(15)BC1a')
  security_hole(0);
else if (version == '12.2(15)BC1')
  security_hole(0);
else if (version == '12.2(11)BC3d')
  security_hole(0);
else if (version == '12.2(11)BC3c')
  security_hole(0);
else if (version == '12.2(11)BC3b')
  security_hole(0);
else if (version == '12.2(11)BC3a')
  security_hole(0);
else if (version == '12.2(11)BC3')
  security_hole(0);
else if (version == '12.2(11)BC2a')
  security_hole(0);
else if (version == '12.2(11)BC2')
  security_hole(0);
else if (version == '12.2(11)BC1b')
  security_hole(0);
else if (version == '12.2(11)BC1a')
  security_hole(0);
else if (version == '12.2(11)BC1')
  security_hole(0);
else if (version == '12.2(8)BC2a')
  security_hole(0);
else if (version == '12.2(8)BC2')
  security_hole(0);
else if (version == '12.2(8)BC1')
  security_hole(0);
else if (version == '12.2(4)BC1b')
  security_hole(0);
else if (version == '12.2(4)BC1a')
  security_hole(0);
else if (version == '12.2(4)BC1')
  security_hole(0);
else if (version == '12.2(16)B2')
  security_hole(0);
else if (version == '12.2(16)B1')
  security_hole(0);
else if (version == '12.2(16)B')
  security_hole(0);
else if (version == '12.2(15)B')
  security_hole(0);
else if (version == '12.2(4)B8')
  security_hole(0);
else if (version == '12.2(4)B7')
  security_hole(0);
else if (version == '12.2(4)B6')
  security_hole(0);
else if (version == '12.2(4)B5')
  security_hole(0);
else if (version == '12.2(4)B4')
  security_hole(0);
else if (version == '12.2(4)B3')
  security_hole(0);
else if (version == '12.2(4)B2')
  security_hole(0);
else if (version == '12.2(4)B1')
  security_hole(0);
else if (version == '12.2(4)B')
  security_hole(0);
else if (version == '12.2(2)B7')
  security_hole(0);
else if (version == '12.2(2)B6')
  security_hole(0);
else if (version == '12.2(2)B5')
  security_hole(0);
else if (version == '12.2(2)B4')
  security_hole(0);
else if (version == '12.2(2)B3')
  security_hole(0);
else if (version == '12.2(2)B2')
  security_hole(0);
else if (version == '12.2(2)B1')
  security_hole(0);
else if (version == '12.2(2)B')
  security_hole(0);
else if (version == '12.2(46a)')
  security_hole(0);
else if (version == '12.2(46)')
  security_hole(0);
else if (version == '12.2(40a)')
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
else if (version == '12.2(29b)')
  security_hole(0);
else if (version == '12.2(29a)')
  security_hole(0);
else if (version == '12.2(29)')
  security_hole(0);
else if (version == '12.2(28d)')
  security_hole(0);
else if (version == '12.2(28c)')
  security_hole(0);
else if (version == '12.2(28b)')
  security_hole(0);
else if (version == '12.2(28a)')
  security_hole(0);
else if (version == '12.2(28)')
  security_hole(0);
else if (version == '12.2(27c)')
  security_hole(0);
else if (version == '12.2(27b)')
  security_hole(0);
else if (version == '12.2(27a)')
  security_hole(0);
else if (version == '12.2(27)')
  security_hole(0);
else if (version == '12.2(26c)')
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
else if (version == '12.2(7e)')
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
else if (version == '12.2(5c)')
  security_hole(0);
else if (version == '12.2(5b)')
  security_hole(0);
else if (version == '12.2(5a)')
  security_hole(0);
else if (version == '12.2(5)')
  security_hole(0);
else if (version == '12.2(3g)')
  security_hole(0);
else if (version == '12.2(3d)')
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
else if (version == '12.1(11)YJ4')
  security_hole(0);
else if (version == '12.1(11)YJ3')
  security_hole(0);
else if (version == '12.1(11)YJ2')
  security_hole(0);
else if (version == '12.1(11)YJ')
  security_hole(0);
else if (version == '12.1(5)YI2')
  security_hole(0);
else if (version == '12.1(5)YI1')
  security_hole(0);
else if (version == '12.1(5)YI')
  security_hole(0);
else if (version == '12.1(5)YH4')
  security_hole(0);
else if (version == '12.1(5)YH3')
  security_hole(0);
else if (version == '12.1(5)YH2')
  security_hole(0);
else if (version == '12.1(5)YH1')
  security_hole(0);
else if (version == '12.1(5)YH')
  security_hole(0);
else if (version == '12.1(5)YF4')
  security_hole(0);
else if (version == '12.1(5)YF3')
  security_hole(0);
else if (version == '12.1(5)YF2')
  security_hole(0);
else if (version == '12.1(5)YF1')
  security_hole(0);
else if (version == '12.1(5)YF')
  security_hole(0);
else if (version == '12.1(5)YE5')
  security_hole(0);
else if (version == '12.1(5)YE4')
  security_hole(0);
else if (version == '12.1(5)YE3')
  security_hole(0);
else if (version == '12.1(5)YE2')
  security_hole(0);
else if (version == '12.1(5)YE1')
  security_hole(0);
else if (version == '12.1(5)YD6')
  security_hole(0);
else if (version == '12.1(5)YD5')
  security_hole(0);
else if (version == '12.1(5)YD4')
  security_hole(0);
else if (version == '12.1(5)YD3')
  security_hole(0);
else if (version == '12.1(5)YD2')
  security_hole(0);
else if (version == '12.1(5)YD1')
  security_hole(0);
else if (version == '12.1(5)YD')
  security_hole(0);
else if (version == '12.1(5)YC3')
  security_hole(0);
else if (version == '12.1(5)YC2')
  security_hole(0);
else if (version == '12.1(5)YC1')
  security_hole(0);
else if (version == '12.1(5)YC')
  security_hole(0);
else if (version == '12.1(5)YB5')
  security_hole(0);
else if (version == '12.1(5)YB4')
  security_hole(0);
else if (version == '12.1(5)YB3')
  security_hole(0);
else if (version == '12.1(5)YB1')
  security_hole(0);
else if (version == '12.1(5)YB')
  security_hole(0);
else if (version == '12.1(5)YA2')
  security_hole(0);
else if (version == '12.1(5)YA1')
  security_hole(0);
else if (version == '12.1(5)YA')
  security_hole(0);
else if (version == '12.1(4)XZ7')
  security_hole(0);
else if (version == '12.1(4)XZ6')
  security_hole(0);
else if (version == '12.1(4)XZ5')
  security_hole(0);
else if (version == '12.1(4)XZ4')
  security_hole(0);
else if (version == '12.1(4)XZ3')
  security_hole(0);
else if (version == '12.1(4)XZ2')
  security_hole(0);
else if (version == '12.1(4)XZ1')
  security_hole(0);
else if (version == '12.1(4)XZ')
  security_hole(0);
else if (version == '12.1(4)XY8')
  security_hole(0);
else if (version == '12.1(4)XY7')
  security_hole(0);
else if (version == '12.1(4)XY6')
  security_hole(0);
else if (version == '12.1(4)XY5')
  security_hole(0);
else if (version == '12.1(4)XY4')
  security_hole(0);
else if (version == '12.1(4)XY3')
  security_hole(0);
else if (version == '12.1(4)XY1')
  security_hole(0);
else if (version == '12.1(4)XY')
  security_hole(0);
else if (version == '12.1(5)XX3')
  security_hole(0);
else if (version == '12.1(5)XX2')
  security_hole(0);
else if (version == '12.1(5)XX1')
  security_hole(0);
else if (version == '12.1(5)XX')
  security_hole(0);
else if (version == '12.1(3)XW2')
  security_hole(0);
else if (version == '12.1(3)XW1')
  security_hole(0);
else if (version == '12.1(3)XW')
  security_hole(0);
else if (version == '12.1(5)XV4')
  security_hole(0);
else if (version == '12.1(5)XV2')
  security_hole(0);
else if (version == '12.1(5)XV1')
  security_hole(0);
else if (version == '12.1(5)XV')
  security_hole(0);
else if (version == '12.1(5)XU1')
  security_hole(0);
else if (version == '12.1(5)XU')
  security_hole(0);
else if (version == '12.1(3)XT2')
  security_hole(0);
else if (version == '12.1(3)XT1')
  security_hole(0);
else if (version == '12.1(3)XT')
  security_hole(0);
else if (version == '12.1(2)XT2')
  security_hole(0);
else if (version == '12.1(5)XS5')
  security_hole(0);
else if (version == '12.1(5)XS4')
  security_hole(0);
else if (version == '12.1(5)XS3')
  security_hole(0);
else if (version == '12.1(5)XS2')
  security_hole(0);
else if (version == '12.1(5)XS1')
  security_hole(0);
else if (version == '12.1(5)XS')
  security_hole(0);
else if (version == '12.1(3)XS')
  security_hole(0);
else if (version == '12.1(5)XR2')
  security_hole(0);
else if (version == '12.1(5)XR1')
  security_hole(0);
else if (version == '12.1(5)XR')
  security_hole(0);
else if (version == '12.1(3)XQ3')
  security_hole(0);
else if (version == '12.1(3)XQ2')
  security_hole(0);
else if (version == '12.1(3)XQ1')
  security_hole(0);
else if (version == '12.1(3)XQ')
  security_hole(0);
else if (version == '12.1(3)XP4')
  security_hole(0);
else if (version == '12.1(3)XP3')
  security_hole(0);
else if (version == '12.1(3)XP2')
  security_hole(0);
else if (version == '12.1(3)XP1')
  security_hole(0);
else if (version == '12.1(3)XP')
  security_hole(0);
else if (version == '12.1(5)XM8')
  security_hole(0);
else if (version == '12.1(5)XM7')
  security_hole(0);
else if (version == '12.1(5)XM6')
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
else if (version == '12.1(3a)XL3')
  security_hole(0);
else if (version == '12.1(3a)XL2')
  security_hole(0);
else if (version == '12.1(3a)XL1')
  security_hole(0);
else if (version == '12.1(3)XL')
  security_hole(0);
else if (version == '12.1(3)XJ')
  security_hole(0);
else if (version == '12.1(3a)XI9')
  security_hole(0);
else if (version == '12.1(3a)XI8')
  security_hole(0);
else if (version == '12.1(3a)XI7')
  security_hole(0);
else if (version == '12.1(3a)XI6')
  security_hole(0);
else if (version == '12.1(3a)XI5')
  security_hole(0);
else if (version == '12.1(3a)XI4')
  security_hole(0);
else if (version == '12.1(3a)XI3')
  security_hole(0);
else if (version == '12.1(3a)XI2')
  security_hole(0);
else if (version == '12.1(3a)XI1')
  security_hole(0);
else if (version == '12.1(3)XI')
  security_hole(0);
else if (version == '12.1(2a)XH3')
  security_hole(0);
else if (version == '12.1(2a)XH2')
  security_hole(0);
else if (version == '12.1(2a)XH1')
  security_hole(0);
else if (version == '12.1(2a)XH')
  security_hole(0);
else if (version == '12.1(3)XG6')
  security_hole(0);
else if (version == '12.1(3)XG5')
  security_hole(0);
else if (version == '12.1(3)XG4')
  security_hole(0);
else if (version == '12.1(3)XG3')
  security_hole(0);
else if (version == '12.1(3)XG2')
  security_hole(0);
else if (version == '12.1(3)XG1')
  security_hole(0);
else if (version == '12.1(3)XG')
  security_hole(0);
else if (version == '12.1(2)XF5')
  security_hole(0);
else if (version == '12.1(2)XF4')
  security_hole(0);
else if (version == '12.1(2)XF3')
  security_hole(0);
else if (version == '12.1(2)XF2')
  security_hole(0);
else if (version == '12.1(2)XF1')
  security_hole(0);
else if (version == '12.1(2)XF')
  security_hole(0);
else if (version == '12.1(1)XE1')
  security_hole(0);
else if (version == '12.1(1)XE')
  security_hole(0);
else if (version == '12.1(1)XD2')
  security_hole(0);
else if (version == '12.1(1)XD1')
  security_hole(0);
else if (version == '12.1(1)XD')
  security_hole(0);
else if (version == '12.1(1)XC1')
  security_hole(0);
else if (version == '12.1(1)XB')
  security_hole(0);
else if (version == '12.1(1)XA4')
  security_hole(0);
else if (version == '12.1(1)XA3')
  security_hole(0);
else if (version == '12.1(1)XA2')
  security_hole(0);
else if (version == '12.1(1)XA')
  security_hole(0);
else if (version == '12.1(5)T9')
  security_hole(0);
else if (version == '12.1(5)T8b')
  security_hole(0);
else if (version == '12.1(5)T8a')
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
else if (version == '12.1(5)T3')
  security_hole(0);
else if (version == '12.1(5)T20')
  security_hole(0);
else if (version == '12.1(5)T2')
  security_hole(0);
else if (version == '12.1(5)T19')
  security_hole(0);
else if (version == '12.1(5)T18')
  security_hole(0);
else if (version == '12.1(5)T17')
  security_hole(0);
else if (version == '12.1(5)T15')
  security_hole(0);
else if (version == '12.1(5)T14')
  security_hole(0);
else if (version == '12.1(5)T12')
  security_hole(0);
else if (version == '12.1(5)T11')
  security_hole(0);
else if (version == '12.1(5)T10')
  security_hole(0);
else if (version == '12.1(5)T1')
  security_hole(0);
else if (version == '12.1(5)T')
  security_hole(0);
else if (version == '12.1(3a)T8')
  security_hole(0);
else if (version == '12.1(3a)T7')
  security_hole(0);
else if (version == '12.1(3a)T6')
  security_hole(0);
else if (version == '12.1(3a)T5')
  security_hole(0);
else if (version == '12.1(3a)T4')
  security_hole(0);
else if (version == '12.1(3a)T3')
  security_hole(0);
else if (version == '12.1(3a)T2')
  security_hole(0);
else if (version == '12.1(3a)T1')
  security_hole(0);
else if (version == '12.1(3)T')
  security_hole(0);
else if (version == '12.1(2a)T2')
  security_hole(0);
else if (version == '12.1(2a)T1')
  security_hole(0);
else if (version == '12.1(2)T')
  security_hole(0);
else if (version == '12.1(1a)T1')
  security_hole(0);
else if (version == '12.1(1)T')
  security_hole(0);
else if (version == '12.1(2)GB')
  security_hole(0);
else if (version == '12.1(1)GA1')
  security_hole(0);
else if (version == '12.1(1)GA')
  security_hole(0);
else if (version == '12.1(6)EZ6')
  security_hole(0);
else if (version == '12.1(6)EZ5')
  security_hole(0);
else if (version == '12.1(6)EZ4')
  security_hole(0);
else if (version == '12.1(6)EZ3')
  security_hole(0);
else if (version == '12.1(6)EZ2')
  security_hole(0);
else if (version == '12.1(6)EZ1')
  security_hole(0);
else if (version == '12.1(6)EZ')
  security_hole(0);
else if (version == '12.1(12c)EY')
  security_hole(0);
else if (version == '12.1(10)EY')
  security_hole(0);
else if (version == '12.1(7a)EY3')
  security_hole(0);
else if (version == '12.1(7a)EY2')
  security_hole(0);
else if (version == '12.1(7a)EY1')
  security_hole(0);
else if (version == '12.1(7a)EY')
  security_hole(0);
else if (version == '12.1(6)EY1')
  security_hole(0);
else if (version == '12.1(6)EY')
  security_hole(0);
else if (version == '12.1(5)EY2')
  security_hole(0);
else if (version == '12.1(5)EY1')
  security_hole(0);
else if (version == '12.1(5)EY')
  security_hole(0);
else if (version == '12.1(13)EX3')
  security_hole(0);
else if (version == '12.1(13)EX2')
  security_hole(0);
else if (version == '12.1(13)EX1')
  security_hole(0);
else if (version == '12.1(13)EX')
  security_hole(0);
else if (version == '12.1(12c)EX1')
  security_hole(0);
else if (version == '12.1(12c)EX')
  security_hole(0);
else if (version == '12.1(11b)EX1')
  security_hole(0);
else if (version == '12.1(11b)EX')
  security_hole(0);
else if (version == '12.1(10)EX2')
  security_hole(0);
else if (version == '12.1(10)EX1')
  security_hole(0);
else if (version == '12.1(10)EX')
  security_hole(0);
else if (version == '12.1(9)EX3')
  security_hole(0);
else if (version == '12.1(9)EX2')
  security_hole(0);
else if (version == '12.1(9)EX1')
  security_hole(0);
else if (version == '12.1(9)EX')
  security_hole(0);
else if (version == '12.1(8b)EX5')
  security_hole(0);
else if (version == '12.1(8b)EX4')
  security_hole(0);
else if (version == '12.1(8b)EX3')
  security_hole(0);
else if (version == '12.1(8b)EX2')
  security_hole(0);
else if (version == '12.1(8a)EX1')
  security_hole(0);
else if (version == '12.1(8a)EX')
  security_hole(0);
else if (version == '12.1(5c)EX3')
  security_hole(0);
else if (version == '12.1(1)EX1')
  security_hole(0);
else if (version == '12.1(1)EX')
  security_hole(0);
else if (version == '12.1(20)EW4')
  security_hole(0);
else if (version == '12.1(20)EW3')
  security_hole(0);
else if (version == '12.1(20)EW2')
  security_hole(0);
else if (version == '12.1(20)EW1')
  security_hole(0);
else if (version == '12.1(20)EW')
  security_hole(0);
else if (version == '12.1(19)EW3')
  security_hole(0);
else if (version == '12.1(19)EW2')
  security_hole(0);
else if (version == '12.1(19)EW1')
  security_hole(0);
else if (version == '12.1(19)EW')
  security_hole(0);
else if (version == '12.1(13)EW4')
  security_hole(0);
else if (version == '12.1(13)EW3')
  security_hole(0);
else if (version == '12.1(13)EW2')
  security_hole(0);
else if (version == '12.1(13)EW1')
  security_hole(0);
else if (version == '12.1(13)EW')
  security_hole(0);
else if (version == '12.1(12c)EW4')
  security_hole(0);
else if (version == '12.1(12c)EW3')
  security_hole(0);
else if (version == '12.1(12c)EW2')
  security_hole(0);
else if (version == '12.1(12c)EW1')
  security_hole(0);
else if (version == '12.1(12c)EW')
  security_hole(0);
else if (version == '12.1(11b)EW1')
  security_hole(0);
else if (version == '12.1(11b)EW')
  security_hole(0);
else if (version == '12.1(8a)EW1')
  security_hole(0);
else if (version == '12.1(8a)EW')
  security_hole(0);
else if (version == '12.1(12c)EV3')
  security_hole(0);
else if (version == '12.1(12c)EV2')
  security_hole(0);
else if (version == '12.1(12c)EV1')
  security_hole(0);
else if (version == '12.1(12c)EV')
  security_hole(0);
else if (version == '12.1(10)EV4')
  security_hole(0);
else if (version == '12.1(10)EV3')
  security_hole(0);
else if (version == '12.1(10)EV2')
  security_hole(0);
else if (version == '12.1(10)EV1a')
  security_hole(0);
else if (version == '12.1(10)EV1')
  security_hole(0);
else if (version == '12.1(10)EV')
  security_hole(0);
else if (version == '12.1(20)EU1')
  security_hole(0);
else if (version == '12.1(20)EU')
  security_hole(0);
else if (version == '12.1(20)EO3')
  security_hole(0);
else if (version == '12.1(20)EO2')
  security_hole(0);
else if (version == '12.1(20)EO1')
  security_hole(0);
else if (version == '12.1(20)EO')
  security_hole(0);
else if (version == '12.1(19)EO6')
  security_hole(0);
else if (version == '12.1(19)EO5')
  security_hole(0);
else if (version == '12.1(19)EO4')
  security_hole(0);
else if (version == '12.1(19)EO3')
  security_hole(0);
else if (version == '12.1(19)EO2')
  security_hole(0);
else if (version == '12.1(19)EO1')
  security_hole(0);
else if (version == '12.1(19)EO')
  security_hole(0);
else if (version == '12.1(14)EO1')
  security_hole(0);
else if (version == '12.1(14)EO')
  security_hole(0);
else if (version == '12.1(22)EC1')
  security_hole(0);
else if (version == '12.1(22)EC')
  security_hole(0);
else if (version == '12.1(20)EC3')
  security_hole(0);
else if (version == '12.1(20)EC2')
  security_hole(0);
else if (version == '12.1(20)EC1')
  security_hole(0);
else if (version == '12.1(20)EC')
  security_hole(0);
else if (version == '12.1(19)EC1')
  security_hole(0);
else if (version == '12.1(19)EC')
  security_hole(0);
else if (version == '12.1(13)EC4')
  security_hole(0);
else if (version == '12.1(13)EC3')
  security_hole(0);
else if (version == '12.1(13)EC2')
  security_hole(0);
else if (version == '12.1(13)EC1')
  security_hole(0);
else if (version == '12.1(13)EC')
  security_hole(0);
else if (version == '12.1(12c)EC1')
  security_hole(0);
else if (version == '12.1(12c)EC')
  security_hole(0);
else if (version == '12.1(11b)EC1')
  security_hole(0);
else if (version == '12.1(11b)EC')
  security_hole(0);
else if (version == '12.1(10)EC1')
  security_hole(0);
else if (version == '12.1(10)EC')
  security_hole(0);
else if (version == '12.1(9)EC1')
  security_hole(0);
else if (version == '12.1(8)EC1')
  security_hole(0);
else if (version == '12.1(8)EC')
  security_hole(0);
else if (version == '12.1(7)EC')
  security_hole(0);
else if (version == '12.1(6)EC1')
  security_hole(0);
else if (version == '12.1(6)EC')
  security_hole(0);
else if (version == '12.1(5)EC1')
  security_hole(0);
else if (version == '12.1(5)EC')
  security_hole(0);
else if (version == '12.1(4)EC')
  security_hole(0);
else if (version == '12.1(3a)EC1')
  security_hole(0);
else if (version == '12.1(3a)EC')
  security_hole(0);
else if (version == '12.1(2)EC1')
  security_hole(0);
else if (version == '12.1(2)EC')
  security_hole(0);
else if (version == '12.1(26)EB1')
  security_hole(0);
else if (version == '12.1(26)EB')
  security_hole(0);
else if (version == '12.1(23)EB')
  security_hole(0);
else if (version == '12.1(22)EB')
  security_hole(0);
else if (version == '12.1(20)EB')
  security_hole(0);
else if (version == '12.1(19)EB')
  security_hole(0);
else if (version == '12.1(14)EB1')
  security_hole(0);
else if (version == '12.1(14)EB')
  security_hole(0);
else if (version == '12.1(13)EB1')
  security_hole(0);
else if (version == '12.1(13)EB')
  security_hole(0);
else if (version == '12.1(22)EA9')
  security_hole(0);
else if (version == '12.1(22)EA8a')
  security_hole(0);
else if (version == '12.1(22)EA8')
  security_hole(0);
else if (version == '12.1(22)EA7')
  security_hole(0);
else if (version == '12.1(22)EA6a')
  security_hole(0);
else if (version == '12.1(22)EA6')
  security_hole(0);
else if (version == '12.1(22)EA5a')
  security_hole(0);
else if (version == '12.1(22)EA5')
  security_hole(0);
else if (version == '12.1(22)EA4a')
  security_hole(0);
else if (version == '12.1(22)EA4')
  security_hole(0);
else if (version == '12.1(22)EA3')
  security_hole(0);
else if (version == '12.1(22)EA2')
  security_hole(0);
else if (version == '12.1(22)EA12')
  security_hole(0);
else if (version == '12.1(22)EA11')
  security_hole(0);
else if (version == '12.1(22)EA10b')
  security_hole(0);
else if (version == '12.1(22)EA10a')
  security_hole(0);
else if (version == '12.1(22)EA10')
  security_hole(0);
else if (version == '12.1(22)EA1b')
  security_hole(0);
else if (version == '12.1(22)EA1a')
  security_hole(0);
else if (version == '12.1(22)EA1')
  security_hole(0);
else if (version == '12.1(20)EA2')
  security_hole(0);
else if (version == '12.1(20)EA1a')
  security_hole(0);
else if (version == '12.1(20)EA1')
  security_hole(0);
else if (version == '12.1(19)EA1d')
  security_hole(0);
else if (version == '12.1(19)EA1c')
  security_hole(0);
else if (version == '12.1(19)EA1b')
  security_hole(0);
else if (version == '12.1(19)EA1a')
  security_hole(0);
else if (version == '12.1(19)EA1')
  security_hole(0);
else if (version == '12.1(14)EA1b')
  security_hole(0);
else if (version == '12.1(14)EA1a')
  security_hole(0);
else if (version == '12.1(14)EA1')
  security_hole(0);
else if (version == '12.1(13)EA1c')
  security_hole(0);
else if (version == '12.1(13)EA1b')
  security_hole(0);
else if (version == '12.1(13)EA1a')
  security_hole(0);
else if (version == '12.1(13)EA1')
  security_hole(0);
else if (version == '12.1(12c)EA1a')
  security_hole(0);
else if (version == '12.1(12c)EA1')
  security_hole(0);
else if (version == '12.1(11)EA1a')
  security_hole(0);
else if (version == '12.1(11)EA1')
  security_hole(0);
else if (version == '12.1(9)EA1')
  security_hole(0);
else if (version == '12.1(8)EA1c')
  security_hole(0);
else if (version == '12.1(6)EA1')
  security_hole(0);
else if (version == '12.1(27b)E4')
  security_hole(0);
else if (version == '12.1(27b)E3')
  security_hole(0);
else if (version == '12.1(27b)E2')
  security_hole(0);
else if (version == '12.1(27b)E1')
  security_hole(0);
else if (version == '12.1(27b)E')
  security_hole(0);
else if (version == '12.1(26)E9')
  security_hole(0);
else if (version == '12.1(26)E8')
  security_hole(0);
else if (version == '12.1(26)E7')
  security_hole(0);
else if (version == '12.1(26)E6')
  security_hole(0);
else if (version == '12.1(26)E5')
  security_hole(0);
else if (version == '12.1(26)E4')
  security_hole(0);
else if (version == '12.1(26)E3')
  security_hole(0);
else if (version == '12.1(26)E2')
  security_hole(0);
else if (version == '12.1(26)E1')
  security_hole(0);
else if (version == '12.1(26)E')
  security_hole(0);
else if (version == '12.1(23)E4')
  security_hole(0);
else if (version == '12.1(23)E3')
  security_hole(0);
else if (version == '12.1(23)E2')
  security_hole(0);
else if (version == '12.1(23)E1')
  security_hole(0);
else if (version == '12.1(23)E')
  security_hole(0);
else if (version == '12.1(22)E6')
  security_hole(0);
else if (version == '12.1(22)E5')
  security_hole(0);
else if (version == '12.1(22)E4')
  security_hole(0);
else if (version == '12.1(22)E3')
  security_hole(0);
else if (version == '12.1(22)E2')
  security_hole(0);
else if (version == '12.1(22)E1')
  security_hole(0);
else if (version == '12.1(22)E')
  security_hole(0);
else if (version == '12.1(20)E6')
  security_hole(0);
else if (version == '12.1(20)E5')
  security_hole(0);
else if (version == '12.1(20)E4')
  security_hole(0);
else if (version == '12.1(20)E3')
  security_hole(0);
else if (version == '12.1(20)E2')
  security_hole(0);
else if (version == '12.1(20)E1')
  security_hole(0);
else if (version == '12.1(20)E')
  security_hole(0);
else if (version == '12.1(19)E7')
  security_hole(0);
else if (version == '12.1(19)E6')
  security_hole(0);
else if (version == '12.1(19)E4')
  security_hole(0);
else if (version == '12.1(19)E3')
  security_hole(0);
else if (version == '12.1(19)E2')
  security_hole(0);
else if (version == '12.1(19)E1')
  security_hole(0);
else if (version == '12.1(19)E')
  security_hole(0);
else if (version == '12.1(14)E7')
  security_hole(0);
else if (version == '12.1(14)E6')
  security_hole(0);
else if (version == '12.1(14)E5')
  security_hole(0);
else if (version == '12.1(14)E4')
  security_hole(0);
else if (version == '12.1(14)E3')
  security_hole(0);
else if (version == '12.1(14)E2')
  security_hole(0);
else if (version == '12.1(14)E10')
  security_hole(0);
else if (version == '12.1(14)E1')
  security_hole(0);
else if (version == '12.1(14)E')
  security_hole(0);
else if (version == '12.1(13)E9')
  security_hole(0);
else if (version == '12.1(13)E8')
  security_hole(0);
else if (version == '12.1(13)E7')
  security_hole(0);
else if (version == '12.1(13)E6')
  security_hole(0);
else if (version == '12.1(13)E5')
  security_hole(0);
else if (version == '12.1(13)E4')
  security_hole(0);
else if (version == '12.1(13)E3')
  security_hole(0);
else if (version == '12.1(13)E2')
  security_hole(0);
else if (version == '12.1(13)E17')
  security_hole(0);
else if (version == '12.1(13)E16')
  security_hole(0);
else if (version == '12.1(13)E15')
  security_hole(0);
else if (version == '12.1(13)E14')
  security_hole(0);
else if (version == '12.1(13)E13')
  security_hole(0);
else if (version == '12.1(13)E12')
  security_hole(0);
else if (version == '12.1(13)E11')
  security_hole(0);
else if (version == '12.1(13)E10')
  security_hole(0);
else if (version == '12.1(13)E1')
  security_hole(0);
else if (version == '12.1(13)E')
  security_hole(0);
else if (version == '12.1(12c)E6')
  security_hole(0);
else if (version == '12.1(12c)E5')
  security_hole(0);
else if (version == '12.1(12c)E4')
  security_hole(0);
else if (version == '12.1(12c)E3')
  security_hole(0);
else if (version == '12.1(12c)E2')
  security_hole(0);
else if (version == '12.1(12c)E1')
  security_hole(0);
else if (version == '12.1(12c)E')
  security_hole(0);
else if (version == '12.1(11b)E7')
  security_hole(0);
else if (version == '12.1(11b)E5')
  security_hole(0);
else if (version == '12.1(11b)E4')
  security_hole(0);
else if (version == '12.1(11b)E3')
  security_hole(0);
else if (version == '12.1(11b)E2')
  security_hole(0);
else if (version == '12.1(11b)E14')
  security_hole(0);
else if (version == '12.1(11b)E12')
  security_hole(0);
else if (version == '12.1(11b)E11')
  security_hole(0);
else if (version == '12.1(11b)E10')
  security_hole(0);
else if (version == '12.1(11b)E1')
  security_hole(0);
else if (version == '12.1(11b)E0a')
  security_hole(0);
else if (version == '12.1(11b)E')
  security_hole(0);
else if (version == '12.1(10)E8')
  security_hole(0);
else if (version == '12.1(10)E7')
  security_hole(0);
else if (version == '12.1(10)E6a')
  security_hole(0);
else if (version == '12.1(10)E6')
  security_hole(0);
else if (version == '12.1(10)E5')
  security_hole(0);
else if (version == '12.1(10)E4')
  security_hole(0);
else if (version == '12.1(10)E3')
  security_hole(0);
else if (version == '12.1(10)E2')
  security_hole(0);
else if (version == '12.1(10)E1')
  security_hole(0);
else if (version == '12.1(10)E')
  security_hole(0);
else if (version == '12.1(9)E3')
  security_hole(0);
else if (version == '12.1(9)E2')
  security_hole(0);
else if (version == '12.1(9)E1')
  security_hole(0);
else if (version == '12.1(9)E')
  security_hole(0);
else if (version == '12.1(8b)E9')
  security_hole(0);
else if (version == '12.1(8b)E8')
  security_hole(0);
else if (version == '12.1(8b)E7')
  security_hole(0);
else if (version == '12.1(8b)E6')
  security_hole(0);
else if (version == '12.1(8b)E20')
  security_hole(0);
else if (version == '12.1(8b)E19')
  security_hole(0);
else if (version == '12.1(8b)E18')
  security_hole(0);
else if (version == '12.1(8b)E15')
  security_hole(0);
else if (version == '12.1(8b)E14')
  security_hole(0);
else if (version == '12.1(8b)E13')
  security_hole(0);
else if (version == '12.1(8b)E12')
  security_hole(0);
else if (version == '12.1(8b)E11')
  security_hole(0);
else if (version == '12.1(8b)E10')
  security_hole(0);
else if (version == '12.1(8a)E5')
  security_hole(0);
else if (version == '12.1(8a)E4')
  security_hole(0);
else if (version == '12.1(8a)E3')
  security_hole(0);
else if (version == '12.1(8a)E2')
  security_hole(0);
else if (version == '12.1(8a)E1')
  security_hole(0);
else if (version == '12.1(8a)E')
  security_hole(0);
else if (version == '12.1(7a)E6')
  security_hole(0);
else if (version == '12.1(7a)E5')
  security_hole(0);
else if (version == '12.1(7a)E4')
  security_hole(0);
else if (version == '12.1(7a)E3')
  security_hole(0);
else if (version == '12.1(7a)E2')
  security_hole(0);
else if (version == '12.1(7a)E1a')
  security_hole(0);
else if (version == '12.1(7a)E1')
  security_hole(0);
else if (version == '12.1(7)E0a')
  security_hole(0);
else if (version == '12.1(7)E')
  security_hole(0);
else if (version == '12.1(6)E8')
  security_hole(0);
else if (version == '12.1(6)E6')
  security_hole(0);
else if (version == '12.1(6)E5')
  security_hole(0);
else if (version == '12.1(6)E4')
  security_hole(0);
else if (version == '12.1(6)E3')
  security_hole(0);
else if (version == '12.1(6)E2')
  security_hole(0);
else if (version == '12.1(6)E13')
  security_hole(0);
else if (version == '12.1(6)E1')
  security_hole(0);
else if (version == '12.1(6)E')
  security_hole(0);
else if (version == '12.1(5c)E9')
  security_hole(0);
else if (version == '12.1(5c)E8')
  security_hole(0);
else if (version == '12.1(5c)E12')
  security_hole(0);
else if (version == '12.1(5c)E10')
  security_hole(0);
else if (version == '12.1(5b)E7')
  security_hole(0);
else if (version == '12.1(5a)E4')
  security_hole(0);
else if (version == '12.1(5a)E3')
  security_hole(0);
else if (version == '12.1(5a)E2')
  security_hole(0);
else if (version == '12.1(5a)E1')
  security_hole(0);
else if (version == '12.1(5a)E')
  security_hole(0);
else if (version == '12.1(4)E3')
  security_hole(0);
else if (version == '12.1(4)E2')
  security_hole(0);
else if (version == '12.1(4)E1')
  security_hole(0);
else if (version == '12.1(4)E')
  security_hole(0);
else if (version == '12.1(3a)E8')
  security_hole(0);
else if (version == '12.1(3a)E7')
  security_hole(0);
else if (version == '12.1(3a)E6')
  security_hole(0);
else if (version == '12.1(3a)E5')
  security_hole(0);
else if (version == '12.1(3a)E4')
  security_hole(0);
else if (version == '12.1(3a)E3')
  security_hole(0);
else if (version == '12.1(3a)E1')
  security_hole(0);
else if (version == '12.1(3a)E')
  security_hole(0);
else if (version == '12.1(2)E2')
  security_hole(0);
else if (version == '12.1(2)E1')
  security_hole(0);
else if (version == '12.1(2)E')
  security_hole(0);
else if (version == '12.1(1)E6')
  security_hole(0);
else if (version == '12.1(1)E5')
  security_hole(0);
else if (version == '12.1(1)E4')
  security_hole(0);
else if (version == '12.1(1)E3')
  security_hole(0);
else if (version == '12.1(1)E2')
  security_hole(0);
else if (version == '12.1(1)E1')
  security_hole(0);
else if (version == '12.1(1)E')
  security_hole(0);
else if (version == '12.1(5)DC3')
  security_hole(0);
else if (version == '12.1(5)DC2')
  security_hole(0);
else if (version == '12.1(5)DC1')
  security_hole(0);
else if (version == '12.1(5)DC')
  security_hole(0);
else if (version == '12.1(4)DC3')
  security_hole(0);
else if (version == '12.1(4)DC2')
  security_hole(0);
else if (version == '12.1(3)DC2')
  security_hole(0);
else if (version == '12.1(3)DC1')
  security_hole(0);
else if (version == '12.1(3)DC')
  security_hole(0);
else if (version == '12.1(1)DC2')
  security_hole(0);
else if (version == '12.1(1)DC1')
  security_hole(0);
else if (version == '12.1(1)DC')
  security_hole(0);
else if (version == '12.1(5)DB2')
  security_hole(0);
else if (version == '12.1(5)DB1')
  security_hole(0);
else if (version == '12.1(5)DB')
  security_hole(0);
else if (version == '12.1(4)DB1')
  security_hole(0);
else if (version == '12.1(3)DB1')
  security_hole(0);
else if (version == '12.1(3)DB')
  security_hole(0);
else if (version == '12.1(1)DB2')
  security_hole(0);
else if (version == '12.1(1)DB')
  security_hole(0);
else if (version == '12.1(7)DA3')
  security_hole(0);
else if (version == '12.1(7)DA2')
  security_hole(0);
else if (version == '12.1(7)DA1')
  security_hole(0);
else if (version == '12.1(7)DA')
  security_hole(0);
else if (version == '12.1(6)DA1')
  security_hole(0);
else if (version == '12.1(6)DA')
  security_hole(0);
else if (version == '12.1(5)DA1')
  security_hole(0);
else if (version == '12.1(5)DA')
  security_hole(0);
else if (version == '12.1(4)DA')
  security_hole(0);
else if (version == '12.1(3)DA')
  security_hole(0);
else if (version == '12.1(2)DA')
  security_hole(0);
else if (version == '12.1(1)DA1')
  security_hole(0);
else if (version == '12.1(1)DA')
  security_hole(0);
else if (version == '12.1(7)CX1')
  security_hole(0);
else if (version == '12.1(7)CX')
  security_hole(0);
else if (version == '12.1(4)CX')
  security_hole(0);
else if (version == '12.1(14)AZ')
  security_hole(0);
else if (version == '12.1(22)AY1')
  security_hole(0);
else if (version == '12.1(13)AY')
  security_hole(0);
else if (version == '12.1(14)AX4')
  security_hole(0);
else if (version == '12.1(14)AX3')
  security_hole(0);
else if (version == '12.1(14)AX2')
  security_hole(0);
else if (version == '12.1(14)AX1')
  security_hole(0);
else if (version == '12.1(14)AX')
  security_hole(0);
else if (version == '12.1(11)AX')
  security_hole(0);
else if (version == '12.1(10)AA')
  security_hole(0);
else if (version == '12.1(8)AA1')
  security_hole(0);
else if (version == '12.1(8)AA')
  security_hole(0);
else if (version == '12.1(7)AA')
  security_hole(0);
else if (version == '12.1(6)AA')
  security_hole(0);
else if (version == '12.1(5)AA')
  security_hole(0);
else if (version == '12.1(4)AA')
  security_hole(0);
else if (version == '12.1(3)AA')
  security_hole(0);
else if (version == '12.1(2a)AA')
  security_hole(0);
else if (version == '12.1(1)AA1')
  security_hole(0);
else if (version == '12.1(1)AA')
  security_hole(0);
else if (version == '12.1(27b)')
  security_hole(0);
else if (version == '12.1(27a)')
  security_hole(0);
else if (version == '12.1(27)')
  security_hole(0);
else if (version == '12.1(26)')
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
else if (version == '12.1(12c)')
  security_hole(0);
else if (version == '12.1(12b)')
  security_hole(0);
else if (version == '12.1(12a)')
  security_hole(0);
else if (version == '12.1(12)')
  security_hole(0);
else if (version == '12.1(11b)')
  security_hole(0);
else if (version == '12.1(11a)')
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
else if (version == '12.1(8b)')
  security_hole(0);
else if (version == '12.1(8a)')
  security_hole(0);
else if (version == '12.1(8)')
  security_hole(0);
else if (version == '12.1(7c)')
  security_hole(0);
else if (version == '12.1(7b)')
  security_hole(0);
else if (version == '12.1(7a)')
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
else if (version == '12.1(5d)')
  security_hole(0);
else if (version == '12.1(5c)')
  security_hole(0);
else if (version == '12.1(5b)')
  security_hole(0);
else if (version == '12.1(5a)')
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
else if (version == '12.1(2a)')
  security_hole(0);
else if (version == '12.1(2)')
  security_hole(0);
else if (version == '12.1(1c)')
  security_hole(0);
else if (version == '12.1(1b)')
  security_hole(0);
else if (version == '12.1(1a)')
  security_hole(0);
else if (version == '12.1(1)')
  security_hole(0);
else if (version == '12.0(7)XV')
  security_hole(0);
else if (version == '12.0(5)XT1')
  security_hole(0);
else if (version == '12.0(5)XS2')
  security_hole(0);
else if (version == '12.0(5)XS1')
  security_hole(0);
else if (version == '12.0(7)XR4')
  security_hole(0);
else if (version == '12.0(7)XR3')
  security_hole(0);
else if (version == '12.0(7)XR2')
  security_hole(0);
else if (version == '12.0(7)XR1')
  security_hole(0);
else if (version == '12.0(5)XQ1')
  security_hole(0);
else if (version == '12.0(5)XQ')
  security_hole(0);
else if (version == '12.0(5)XN')
  security_hole(0);
else if (version == '12.0(4)XM1')
  security_hole(0);
else if (version == '12.0(4)XM')
  security_hole(0);
else if (version == '12.0(4)XL1')
  security_hole(0);
else if (version == '12.0(4)XL')
  security_hole(0);
else if (version == '12.0(7)XK3')
  security_hole(0);
else if (version == '12.0(7)XK2')
  security_hole(0);
else if (version == '12.0(7)XK1')
  security_hole(0);
else if (version == '12.0(7)XK')
  security_hole(0);
else if (version == '12.0(5)XK2')
  security_hole(0);
else if (version == '12.0(5)XK1')
  security_hole(0);
else if (version == '12.0(5)XK')
  security_hole(0);
else if (version == '12.0(4)XJ6')
  security_hole(0);
else if (version == '12.0(4)XJ5')
  security_hole(0);
else if (version == '12.0(4)XJ4')
  security_hole(0);
else if (version == '12.0(4)XJ3')
  security_hole(0);
else if (version == '12.0(4)XJ2')
  security_hole(0);
else if (version == '12.0(4)XJ1')
  security_hole(0);
else if (version == '12.0(4)XJ')
  security_hole(0);
else if (version == '12.0(4)XI1')
  security_hole(0);
else if (version == '12.0(4)XI')
  security_hole(0);
else if (version == '12.0(4)XH4')
  security_hole(0);
else if (version == '12.0(4)XH3')
  security_hole(0);
else if (version == '12.0(4)XH1')
  security_hole(0);
else if (version == '12.0(4)XH')
  security_hole(0);
else if (version == '12.0(2)XH')
  security_hole(0);
else if (version == '12.0(3)XG')
  security_hole(0);
else if (version == '12.0(7)XE2')
  security_hole(0);
else if (version == '12.0(7)XE1')
  security_hole(0);
else if (version == '12.0(5)XE8')
  security_hole(0);
else if (version == '12.0(5)XE7')
  security_hole(0);
else if (version == '12.0(5)XE6')
  security_hole(0);
else if (version == '12.0(5)XE5')
  security_hole(0);
else if (version == '12.0(5)XE4')
  security_hole(0);
else if (version == '12.0(5)XE3')
  security_hole(0);
else if (version == '12.0(5)XE2')
  security_hole(0);
else if (version == '12.0(5)XE1')
  security_hole(0);
else if (version == '12.0(5)XE')
  security_hole(0);
else if (version == '12.0(4)XE2')
  security_hole(0);
else if (version == '12.0(4)XE1')
  security_hole(0);
else if (version == '12.0(4)XE')
  security_hole(0);
else if (version == '12.0(3)XE2')
  security_hole(0);
else if (version == '12.0(3)XE1')
  security_hole(0);
else if (version == '12.0(3)XE')
  security_hole(0);
else if (version == '12.0(2)XE4')
  security_hole(0);
else if (version == '12.0(2)XE3')
  security_hole(0);
else if (version == '12.0(2)XE2')
  security_hole(0);
else if (version == '12.0(2)XE1')
  security_hole(0);
else if (version == '12.0(2)XE')
  security_hole(0);
else if (version == '12.0(1)XE')
  security_hole(0);
else if (version == '12.0(2)XD1')
  security_hole(0);
else if (version == '12.0(2)XC2')
  security_hole(0);
else if (version == '12.0(2)XC1')
  security_hole(0);
else if (version == '12.0(2)XC')
  security_hole(0);
else if (version == '12.0(1)XB1')
  security_hole(0);
else if (version == '12.0(1)XB')
  security_hole(0);
else if (version == '12.0(1)XA3')
  security_hole(0);
else if (version == '12.0(1)XA')
  security_hole(0);
else if (version == '12.0(5)WC9a')
  security_hole(0);
else if (version == '12.0(5)WC9')
  security_hole(0);
else if (version == '12.0(5)WC8')
  security_hole(0);
else if (version == '12.0(5)WC7')
  security_hole(0);
else if (version == '12.0(5)WC6')
  security_hole(0);
else if (version == '12.0(5)WC5a')
  security_hole(0);
else if (version == '12.0(5)WC5')
  security_hole(0);
else if (version == '12.0(5)WC4a')
  security_hole(0);
else if (version == '12.0(5)WC4')
  security_hole(0);
else if (version == '12.0(5)WC3a')
  security_hole(0);
else if (version == '12.0(5)WC17')
  security_hole(0);
else if (version == '12.0(5)WC16')
  security_hole(0);
else if (version == '12.0(5)WC15')
  security_hole(0);
else if (version == '12.0(5)WC14')
  security_hole(0);
else if (version == '12.0(5)WC13')
  security_hole(0);
else if (version == '12.0(5)WC12')
  security_hole(0);
else if (version == '12.0(5)WC11')
  security_hole(0);
else if (version == '12.0(5)WC10')
  security_hole(0);
else if (version == '12.0(7)T3')
  security_hole(0);
else if (version == '12.0(7)T2')
  security_hole(0);
else if (version == '12.0(7)T')
  security_hole(0);
else if (version == '12.0(5)T2')
  security_hole(0);
else if (version == '12.0(5)T1')
  security_hole(0);
else if (version == '12.0(5)T')
  security_hole(0);
else if (version == '12.0(4)T1')
  security_hole(0);
else if (version == '12.0(4)T')
  security_hole(0);
else if (version == '12.0(3)T3')
  security_hole(0);
else if (version == '12.0(3)T2')
  security_hole(0);
else if (version == '12.0(3)T1')
  security_hole(0);
else if (version == '12.0(3)T')
  security_hole(0);
else if (version == '12.0(2a)T1')
  security_hole(0);
else if (version == '12.0(2)T1')
  security_hole(0);
else if (version == '12.0(2)T')
  security_hole(0);
else if (version == '12.0(1)T')
  security_hole(0);
else if (version == '12.0(30)SZ9')
  security_hole(0);
else if (version == '12.0(30)SZ8')
  security_hole(0);
else if (version == '12.0(30)SZ6')
  security_hole(0);
else if (version == '12.0(30)SZ5')
  security_hole(0);
else if (version == '12.0(30)SZ4')
  security_hole(0);
else if (version == '12.0(23)SZ3')
  security_hole(0);
else if (version == '12.0(21)SZ')
  security_hole(0);
else if (version == '12.0(32)SY7')
  security_hole(0);
else if (version == '12.0(32)SY6')
  security_hole(0);
else if (version == '12.0(32)SY5')
  security_hole(0);
else if (version == '12.0(32)SY4')
  security_hole(0);
else if (version == '12.0(32)SY3')
  security_hole(0);
else if (version == '12.0(32)SY2')
  security_hole(0);
else if (version == '12.0(32)SY1')
  security_hole(0);
else if (version == '12.0(32)SY')
  security_hole(0);
else if (version == '12.0(25)SX9')
  security_hole(0);
else if (version == '12.0(25)SX8')
  security_hole(0);
else if (version == '12.0(25)SX7')
  security_hole(0);
else if (version == '12.0(25)SX6e')
  security_hole(0);
else if (version == '12.0(25)SX6')
  security_hole(0);
else if (version == '12.0(25)SX5')
  security_hole(0);
else if (version == '12.0(25)SX4')
  security_hole(0);
else if (version == '12.0(25)SX3')
  security_hole(0);
else if (version == '12.0(25)SX2')
  security_hole(0);
else if (version == '12.0(25)SX10')
  security_hole(0);
else if (version == '12.0(25)SX1')
  security_hole(0);
else if (version == '12.0(25)SX')
  security_hole(0);
else if (version == '12.0(23)SX5')
  security_hole(0);
else if (version == '12.0(23)SX4')
  security_hole(0);
else if (version == '12.0(23)SX3')
  security_hole(0);
else if (version == '12.0(23)SX2')
  security_hole(0);
else if (version == '12.0(23)SX1')
  security_hole(0);
else if (version == '12.0(23)SX')
  security_hole(0);
else if (version == '12.0(21)SX1')
  security_hole(0);
else if (version == '12.0(21)SX')
  security_hole(0);
else if (version == '12.0(10)SX')
  security_hole(0);
else if (version == '12.0(28)SW1')
  security_hole(0);
else if (version == '12.0(21)ST7')
  security_hole(0);
else if (version == '12.0(21)ST6a')
  security_hole(0);
else if (version == '12.0(21)ST6')
  security_hole(0);
else if (version == '12.0(21)ST5')
  security_hole(0);
else if (version == '12.0(21)ST4')
  security_hole(0);
else if (version == '12.0(21)ST3a')
  security_hole(0);
else if (version == '12.0(21)ST3')
  security_hole(0);
else if (version == '12.0(21)ST2b')
  security_hole(0);
else if (version == '12.0(21)ST2a')
  security_hole(0);
else if (version == '12.0(21)ST2')
  security_hole(0);
else if (version == '12.0(21)ST1')
  security_hole(0);
else if (version == '12.0(21)ST')
  security_hole(0);
else if (version == '12.0(20)ST6')
  security_hole(0);
else if (version == '12.0(20)ST5')
  security_hole(0);
else if (version == '12.0(20)ST4')
  security_hole(0);
else if (version == '12.0(20)ST3')
  security_hole(0);
else if (version == '12.0(20)ST2')
  security_hole(0);
else if (version == '12.0(20)ST1')
  security_hole(0);
else if (version == '12.0(20)ST')
  security_hole(0);
else if (version == '12.0(19)ST6')
  security_hole(0);
else if (version == '12.0(19)ST5')
  security_hole(0);
else if (version == '12.0(19)ST4')
  security_hole(0);
else if (version == '12.0(19)ST3')
  security_hole(0);
else if (version == '12.0(19)ST2')
  security_hole(0);
else if (version == '12.0(19)ST1')
  security_hole(0);
else if (version == '12.0(19)ST')
  security_hole(0);
else if (version == '12.0(18)ST1')
  security_hole(0);
else if (version == '12.0(18)ST')
  security_hole(0);
else if (version == '12.0(17)ST8')
  security_hole(0);
else if (version == '12.0(17)ST7')
  security_hole(0);
else if (version == '12.0(17)ST6')
  security_hole(0);
else if (version == '12.0(17)ST5')
  security_hole(0);
else if (version == '12.0(17)ST4')
  security_hole(0);
else if (version == '12.0(17)ST3')
  security_hole(0);
else if (version == '12.0(17)ST2')
  security_hole(0);
else if (version == '12.0(17)ST1')
  security_hole(0);
else if (version == '12.0(17)ST')
  security_hole(0);
else if (version == '12.0(16)ST1')
  security_hole(0);
else if (version == '12.0(16)ST')
  security_hole(0);
else if (version == '12.0(14)ST3')
  security_hole(0);
else if (version == '12.0(14)ST2')
  security_hole(0);
else if (version == '12.0(14)ST1')
  security_hole(0);
else if (version == '12.0(14)ST')
  security_hole(0);
else if (version == '12.0(11)ST4')
  security_hole(0);
else if (version == '12.0(11)ST3')
  security_hole(0);
else if (version == '12.0(11)ST2')
  security_hole(0);
else if (version == '12.0(11)ST1')
  security_hole(0);
else if (version == '12.0(11)ST')
  security_hole(0);
else if (version == '12.0(10)ST2')
  security_hole(0);
else if (version == '12.0(10)ST1')
  security_hole(0);
else if (version == '12.0(10)ST')
  security_hole(0);
else if (version == '12.0(9)ST')
  security_hole(0);
else if (version == '12.0(21)SP4')
  security_hole(0);
else if (version == '12.0(21)SP3')
  security_hole(0);
else if (version == '12.0(21)SP2')
  security_hole(0);
else if (version == '12.0(21)SP1')
  security_hole(0);
else if (version == '12.0(21)SP')
  security_hole(0);
else if (version == '12.0(20)SP2')
  security_hole(0);
else if (version == '12.0(20)SP1')
  security_hole(0);
else if (version == '12.0(20)SP')
  security_hole(0);
else if (version == '12.0(19)SP')
  security_hole(0);
else if (version == '12.0(19)SL4')
  security_hole(0);
else if (version == '12.0(19)SL3')
  security_hole(0);
else if (version == '12.0(19)SL2')
  security_hole(0);
else if (version == '12.0(19)SL1')
  security_hole(0);
else if (version == '12.0(19)SL')
  security_hole(0);
else if (version == '12.0(17)SL8')
  security_hole(0);
else if (version == '12.0(17)SL6')
  security_hole(0);
else if (version == '12.0(17)SL5')
  security_hole(0);
else if (version == '12.0(17)SL4')
  security_hole(0);
else if (version == '12.0(17)SL3')
  security_hole(0);
else if (version == '12.0(17)SL2')
  security_hole(0);
else if (version == '12.0(17)SL1')
  security_hole(0);
else if (version == '12.0(17)SL')
  security_hole(0);
else if (version == '12.0(15)SL')
  security_hole(0);
else if (version == '12.0(14)SL1')
  security_hole(0);
else if (version == '12.0(14)SL')
  security_hole(0);
else if (version == '12.0(11)SL1')
  security_hole(0);
else if (version == '12.0(11)SL')
  security_hole(0);
else if (version == '12.0(10)SL')
  security_hole(0);
else if (version == '12.0(9)SL2')
  security_hole(0);
else if (version == '12.0(9)SL1')
  security_hole(0);
else if (version == '12.0(9)SL')
  security_hole(0);
else if (version == '12.0(16)SC3')
  security_hole(0);
else if (version == '12.0(16)SC2')
  security_hole(0);
else if (version == '12.0(16)SC1')
  security_hole(0);
else if (version == '12.0(16)SC')
  security_hole(0);
else if (version == '12.0(15)SC1')
  security_hole(0);
else if (version == '12.0(15)SC')
  security_hole(0);
else if (version == '12.0(14)SC')
  security_hole(0);
else if (version == '12.0(13)SC')
  security_hole(0);
else if (version == '12.0(12)SC')
  security_hole(0);
else if (version == '12.0(11)SC')
  security_hole(0);
else if (version == '12.0(10)SC1')
  security_hole(0);
else if (version == '12.0(10)SC')
  security_hole(0);
else if (version == '12.0(9)SC')
  security_hole(0);
else if (version == '12.0(8)SC1')
  security_hole(0);
else if (version == '12.0(8)SC')
  security_hole(0);
else if (version == '12.0(7)SC')
  security_hole(0);
else if (version == '12.0(6)SC')
  security_hole(0);
else if (version == '12.0(33)S2')
  security_hole(0);
else if (version == '12.0(33)S1')
  security_hole(0);
else if (version == '12.0(33)S')
  security_hole(0);
else if (version == '12.0(32)S9')
  security_hole(0);
else if (version == '12.0(32)S8')
  security_hole(0);
else if (version == '12.0(32)S7')
  security_hole(0);
else if (version == '12.0(32)S6')
  security_hole(0);
else if (version == '12.0(32)S5')
  security_hole(0);
else if (version == '12.0(32)S4')
  security_hole(0);
else if (version == '12.0(32)S3d')
  security_hole(0);
else if (version == '12.0(32)S3')
  security_hole(0);
else if (version == '12.0(32)S2')
  security_hole(0);
else if (version == '12.0(32)S11')
  security_hole(0);
else if (version == '12.0(32)S10')
  security_hole(0);
else if (version == '12.0(32)S1')
  security_hole(0);
else if (version == '12.0(32)S')
  security_hole(0);
else if (version == '12.0(31)S6')
  security_hole(0);
else if (version == '12.0(31)S5')
  security_hole(0);
else if (version == '12.0(31)S4')
  security_hole(0);
else if (version == '12.0(31)S3')
  security_hole(0);
else if (version == '12.0(31)S2')
  security_hole(0);
else if (version == '12.0(31)S1')
  security_hole(0);
else if (version == '12.0(31)S')
  security_hole(0);
else if (version == '12.0(30)S5')
  security_hole(0);
else if (version == '12.0(30)S4')
  security_hole(0);
else if (version == '12.0(30)S3')
  security_hole(0);
else if (version == '12.0(30)S2')
  security_hole(0);
else if (version == '12.0(30)S1')
  security_hole(0);
else if (version == '12.0(30)S')
  security_hole(0);
else if (version == '12.0(29)S1')
  security_hole(0);
else if (version == '12.0(29)S')
  security_hole(0);
else if (version == '12.0(28)S6')
  security_hole(0);
else if (version == '12.0(28)S5')
  security_hole(0);
else if (version == '12.0(28)S4')
  security_hole(0);
else if (version == '12.0(28)S3')
  security_hole(0);
else if (version == '12.0(28)S2')
  security_hole(0);
else if (version == '12.0(28)S1')
  security_hole(0);
else if (version == '12.0(28)S')
  security_hole(0);
else if (version == '12.0(27)S5')
  security_hole(0);
else if (version == '12.0(27)S4')
  security_hole(0);
else if (version == '12.0(27)S3')
  security_hole(0);
else if (version == '12.0(27)S2a')
  security_hole(0);
else if (version == '12.0(27)S2')
  security_hole(0);
else if (version == '12.0(27)S1')
  security_hole(0);
else if (version == '12.0(27)S')
  security_hole(0);
else if (version == '12.0(26)S6')
  security_hole(0);
else if (version == '12.0(26)S5')
  security_hole(0);
else if (version == '12.0(26)S4')
  security_hole(0);
else if (version == '12.0(26)S3')
  security_hole(0);
else if (version == '12.0(26)S2')
  security_hole(0);
else if (version == '12.0(26)S1')
  security_hole(0);
else if (version == '12.0(26)S')
  security_hole(0);
else if (version == '12.0(25)S4')
  security_hole(0);
else if (version == '12.0(25)S3')
  security_hole(0);
else if (version == '12.0(25)S2')
  security_hole(0);
else if (version == '12.0(25)S1d')
  security_hole(0);
else if (version == '12.0(25)S1c')
  security_hole(0);
else if (version == '12.0(25)S1b')
  security_hole(0);
else if (version == '12.0(25)S1a')
  security_hole(0);
else if (version == '12.0(25)S1')
  security_hole(0);
else if (version == '12.0(25)S')
  security_hole(0);
else if (version == '12.0(24)S6')
  security_hole(0);
else if (version == '12.0(24)S5')
  security_hole(0);
else if (version == '12.0(24)S4a')
  security_hole(0);
else if (version == '12.0(24)S4')
  security_hole(0);
else if (version == '12.0(24)S3')
  security_hole(0);
else if (version == '12.0(24)S2b')
  security_hole(0);
else if (version == '12.0(24)S2a')
  security_hole(0);
else if (version == '12.0(24)S2')
  security_hole(0);
else if (version == '12.0(24)S1')
  security_hole(0);
else if (version == '12.0(24)S')
  security_hole(0);
else if (version == '12.0(23)S6a')
  security_hole(0);
else if (version == '12.0(23)S6')
  security_hole(0);
else if (version == '12.0(23)S5')
  security_hole(0);
else if (version == '12.0(23)S4')
  security_hole(0);
else if (version == '12.0(23)S3c')
  security_hole(0);
else if (version == '12.0(23)S3b')
  security_hole(0);
else if (version == '12.0(23)S3a')
  security_hole(0);
else if (version == '12.0(23)S3')
  security_hole(0);
else if (version == '12.0(23)S2a')
  security_hole(0);
else if (version == '12.0(23)S2')
  security_hole(0);
else if (version == '12.0(23)S1')
  security_hole(0);
else if (version == '12.0(23)S')
  security_hole(0);
else if (version == '12.0(22)S6')
  security_hole(0);
else if (version == '12.0(22)S5a')
  security_hole(0);
else if (version == '12.0(22)S5')
  security_hole(0);
else if (version == '12.0(22)S4a')
  security_hole(0);
else if (version == '12.0(22)S4')
  security_hole(0);
else if (version == '12.0(22)S3c')
  security_hole(0);
else if (version == '12.0(22)S3b')
  security_hole(0);
else if (version == '12.0(22)S3a')
  security_hole(0);
else if (version == '12.0(22)S3')
  security_hole(0);
else if (version == '12.0(22)S2e')
  security_hole(0);
else if (version == '12.0(22)S2d')
  security_hole(0);
else if (version == '12.0(22)S2c')
  security_hole(0);
else if (version == '12.0(22)S2b')
  security_hole(0);
else if (version == '12.0(22)S2a')
  security_hole(0);
else if (version == '12.0(22)S2')
  security_hole(0);
else if (version == '12.0(22)S1')
  security_hole(0);
else if (version == '12.0(22)S')
  security_hole(0);
else if (version == '12.0(21)S8')
  security_hole(0);
else if (version == '12.0(21)S7')
  security_hole(0);
else if (version == '12.0(21)S6a')
  security_hole(0);
else if (version == '12.0(21)S6')
  security_hole(0);
else if (version == '12.0(21)S5a')
  security_hole(0);
else if (version == '12.0(21)S5')
  security_hole(0);
else if (version == '12.0(21)S4a')
  security_hole(0);
else if (version == '12.0(21)S4')
  security_hole(0);
else if (version == '12.0(21)S3')
  security_hole(0);
else if (version == '12.0(21)S2')
  security_hole(0);
else if (version == '12.0(21)S1')
  security_hole(0);
else if (version == '12.0(21)S')
  security_hole(0);
else if (version == '12.0(19)S4')
  security_hole(0);
else if (version == '12.0(19)S3')
  security_hole(0);
else if (version == '12.0(19)S2a')
  security_hole(0);
else if (version == '12.0(19)S2')
  security_hole(0);
else if (version == '12.0(19)S1')
  security_hole(0);
else if (version == '12.0(19)S')
  security_hole(0);
else if (version == '12.0(18)S7')
  security_hole(0);
else if (version == '12.0(18)S6')
  security_hole(0);
else if (version == '12.0(18)S5a')
  security_hole(0);
else if (version == '12.0(18)S5')
  security_hole(0);
else if (version == '12.0(18)S4')
  security_hole(0);
else if (version == '12.0(18)S3')
  security_hole(0);
else if (version == '12.0(18)S2')
  security_hole(0);
else if (version == '12.0(18)S1')
  security_hole(0);
else if (version == '12.0(18)S')
  security_hole(0);
else if (version == '12.0(17)S7')
  security_hole(0);
else if (version == '12.0(17)S6')
  security_hole(0);
else if (version == '12.0(17)S5')
  security_hole(0);
else if (version == '12.0(17)S4')
  security_hole(0);
else if (version == '12.0(17)S3')
  security_hole(0);
else if (version == '12.0(17)S2')
  security_hole(0);
else if (version == '12.0(17)S1')
  security_hole(0);
else if (version == '12.0(17)S')
  security_hole(0);
else if (version == '12.0(16)S9')
  security_hole(0);
else if (version == '12.0(16)S8a')
  security_hole(0);
else if (version == '12.0(16)S8')
  security_hole(0);
else if (version == '12.0(16)S7')
  security_hole(0);
else if (version == '12.0(16)S6')
  security_hole(0);
else if (version == '12.0(16)S5')
  security_hole(0);
else if (version == '12.0(16)S4')
  security_hole(0);
else if (version == '12.0(16)S3')
  security_hole(0);
else if (version == '12.0(16)S2')
  security_hole(0);
else if (version == '12.0(16)S10')
  security_hole(0);
else if (version == '12.0(16)S1')
  security_hole(0);
else if (version == '12.0(16)S')
  security_hole(0);
else if (version == '12.0(15)S7')
  security_hole(0);
else if (version == '12.0(15)S6')
  security_hole(0);
else if (version == '12.0(15)S5')
  security_hole(0);
else if (version == '12.0(15)S4')
  security_hole(0);
else if (version == '12.0(15)S3')
  security_hole(0);
else if (version == '12.0(15)S2')
  security_hole(0);
else if (version == '12.0(15)S1')
  security_hole(0);
else if (version == '12.0(15)S')
  security_hole(0);
else if (version == '12.0(14)S8')
  security_hole(0);
else if (version == '12.0(14)S7')
  security_hole(0);
else if (version == '12.0(14)S6')
  security_hole(0);
else if (version == '12.0(14)S5')
  security_hole(0);
else if (version == '12.0(14)S4')
  security_hole(0);
else if (version == '12.0(14)S3')
  security_hole(0);
else if (version == '12.0(14)S2')
  security_hole(0);
else if (version == '12.0(14)S1')
  security_hole(0);
else if (version == '12.0(14)S')
  security_hole(0);
else if (version == '12.0(13)S8')
  security_hole(0);
else if (version == '12.0(13)S6')
  security_hole(0);
else if (version == '12.0(13)S5')
  security_hole(0);
else if (version == '12.0(13)S4')
  security_hole(0);
else if (version == '12.0(13)S3')
  security_hole(0);
else if (version == '12.0(13)S2')
  security_hole(0);
else if (version == '12.0(13)S1')
  security_hole(0);
else if (version == '12.0(13)S')
  security_hole(0);
else if (version == '12.0(12)S4')
  security_hole(0);
else if (version == '12.0(12)S3')
  security_hole(0);
else if (version == '12.0(12)S2')
  security_hole(0);
else if (version == '12.0(12)S1')
  security_hole(0);
else if (version == '12.0(12)S')
  security_hole(0);
else if (version == '12.0(11)S6')
  security_hole(0);
else if (version == '12.0(11)S5')
  security_hole(0);
else if (version == '12.0(11)S4')
  security_hole(0);
else if (version == '12.0(11)S3')
  security_hole(0);
else if (version == '12.0(11)S2')
  security_hole(0);
else if (version == '12.0(11)S1')
  security_hole(0);
else if (version == '12.0(11)S')
  security_hole(0);
else if (version == '12.0(10)S8')
  security_hole(0);
else if (version == '12.0(10)S7')
  security_hole(0);
else if (version == '12.0(10)S5')
  security_hole(0);
else if (version == '12.0(10)S4')
  security_hole(0);
else if (version == '12.0(10)S3b')
  security_hole(0);
else if (version == '12.0(10)S3')
  security_hole(0);
else if (version == '12.0(10)S2')
  security_hole(0);
else if (version == '12.0(10)S1')
  security_hole(0);
else if (version == '12.0(10)S')
  security_hole(0);
else if (version == '12.0(9)S8')
  security_hole(0);
else if (version == '12.0(9)S')
  security_hole(0);
else if (version == '12.0(8)S1')
  security_hole(0);
else if (version == '12.0(8)S')
  security_hole(0);
else if (version == '12.0(7)S1')
  security_hole(0);
else if (version == '12.0(7)S')
  security_hole(0);
else if (version == '12.0(6)S2')
  security_hole(0);
else if (version == '12.0(6)S1')
  security_hole(0);
else if (version == '12.0(6)S')
  security_hole(0);
else if (version == '12.0(5)S')
  security_hole(0);
else if (version == '12.0(4)S')
  security_hole(0);
else if (version == '12.0(3)S')
  security_hole(0);
else if (version == '12.0(2)S')
  security_hole(0);
else if (version == '12.0(7)DC1')
  security_hole(0);
else if (version == '12.0(7)DC')
  security_hole(0);
else if (version == '12.0(7)DB2')
  security_hole(0);
else if (version == '12.0(7)DB1')
  security_hole(0);
else if (version == '12.0(7)DB')
  security_hole(0);
else if (version == '12.0(3)DB')
  security_hole(0);
else if (version == '12.0(2)DB')
  security_hole(0);
else if (version == '12.0(8)DA')
  security_hole(0);
else if (version == '12.0(28d)')
  security_hole(0);
else if (version == '12.0(28c)')
  security_hole(0);
else if (version == '12.0(28b)')
  security_hole(0);
else if (version == '12.0(28a)')
  security_hole(0);
else if (version == '12.0(28)')
  security_hole(0);
else if (version == '12.0(27)')
  security_hole(0);
else if (version == '12.0(26)')
  security_hole(0);
else if (version == '12.0(25)')
  security_hole(0);
else if (version == '12.0(24)')
  security_hole(0);
else if (version == '12.0(23)')
  security_hole(0);
else if (version == '12.0(22)')
  security_hole(0);
else if (version == '12.0(21a)')
  security_hole(0);
else if (version == '12.0(21)')
  security_hole(0);
else if (version == '12.0(20a)')
  security_hole(0);
else if (version == '12.0(20)')
  security_hole(0);
else if (version == '12.0(19b)')
  security_hole(0);
else if (version == '12.0(19a)')
  security_hole(0);
else if (version == '12.0(19)')
  security_hole(0);
else if (version == '12.0(18b)')
  security_hole(0);
else if (version == '12.0(18a)')
  security_hole(0);
else if (version == '12.0(18)')
  security_hole(0);
else if (version == '12.0(17a)')
  security_hole(0);
else if (version == '12.0(17)')
  security_hole(0);
else if (version == '12.0(16a)')
  security_hole(0);
else if (version == '12.0(16)')
  security_hole(0);
else if (version == '12.0(15b)')
  security_hole(0);
else if (version == '12.0(15a)')
  security_hole(0);
else if (version == '12.0(15)')
  security_hole(0);
else if (version == '12.0(14a)')
  security_hole(0);
else if (version == '12.0(14)')
  security_hole(0);
else if (version == '12.0(13a)')
  security_hole(0);
else if (version == '12.0(13)')
  security_hole(0);
else if (version == '12.0(12a)')
  security_hole(0);
else if (version == '12.0(12)')
  security_hole(0);
else if (version == '12.0(11a)')
  security_hole(0);
else if (version == '12.0(11)')
  security_hole(0);
else if (version == '12.0(10a)')
  security_hole(0);
else if (version == '12.0(10)')
  security_hole(0);
else if (version == '12.0(9a)')
  security_hole(0);
else if (version == '12.0(9)')
  security_hole(0);
else if (version == '12.0(8a)')
  security_hole(0);
else if (version == '12.0(8)')
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
else if (version == '12.0(4a)')
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
else if (version == '12.0(1a)')
  security_hole(0);
else if (version == '12.0(1)')
  security_hole(0);
else
  exit(0, 'The host is not affected.');

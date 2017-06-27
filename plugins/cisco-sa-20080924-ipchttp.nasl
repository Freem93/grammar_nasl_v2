#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080a014ae.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49020);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2008-3805", "CVE-2008-3806");
 script_bugtraq_id(31363);
 script_osvdb_id(48740);
 script_name(english:"Cisco 10000, uBR10012, uBR7200 Series Devices IPC Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'Cisco 10000, uBR10012 and uBR7200 series devices use a User Datagram
Protocol (UDP) based Inter-Process Communication (IPC) channel that is
externally reachable. An attacker could exploit this vulnerability to
cause a denial of service (DoS) condition on affected devices. No other
platforms are affected.

 Cisco has released free software updates that address this
vulnerability. Workarounds that mitigate this vulnerability are
available.
');
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?710e01f5");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080a014ae.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?ca03be3a");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-ipc."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2015/01/15 16:37:15 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsg15342");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsh29217");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20080924-ipc");
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2015 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}
include("cisco_func.inc");

#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(1c)')
  security_hole(0);
else if (version == '12.4(1b)')
  security_hole(0);
else if (version == '12.4(1a)')
  security_hole(0);
else if (version == '12.4(1)')
  security_hole(0);
else if (version == '12.3(14)YX5')
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
else if (version == '12.3(7)XI10')
  security_hole(0);
else if (version == '12.3(14)T2')
  security_hole(0);
else if (version == '12.3(14)T1')
  security_hole(0);
else if (version == '12.3(14)T')
  security_hole(0);
else if (version == '12.3(21)BC')
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
else if (version == '12.2(28)ZX')
  security_hole(0);
else if (version == '12.2(28b)ZV1')
  security_hole(0);
else if (version == '12.2(28)ZV2')
  security_hole(0);
else if (version == '12.2(28)VZ')
  security_hole(0);
else if (version == '12.2(33)SRC1')
  security_hole(0);
else if (version == '12.2(33)SRC')
  security_hole(0);
else if (version == '12.2(33)SCA')
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
else if (version == '12.2(31)SB12')
  security_hole(0);
else if (version == '12.2(31)SB11')
  security_hole(0);
else if (version == '12.2(31)SB10')
  security_hole(0);
else if (version == '12.2(28)SB6')
  security_hole(0);
else if (version == '12.2(28)SB5')
  security_hole(0);
else if (version == '12.2(28)SB4')
  security_hole(0);
else if (version == '12.2(28)SB3')
  security_hole(0);
else if (version == '12.2(28)SB2')
  security_hole(0);
else if (version == '12.2(28)SB')
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
else if (version == '12.0(28)S6')
  security_hole(0);
else if (version == '12.0(28)S5')
  security_hole(0);
else if (version == '12.0(28)S4')
  security_hole(0);
else if (version == '12.0(28)S3')
  security_hole(0);
else if (version == '12.0(27)S5')
  security_hole(0);
else
  exit(0, 'The host is not affected.');

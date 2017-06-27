#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00807e0a5b.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49000);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2007-0917", "CVE-2007-0918");
 script_bugtraq_id(22549);
 script_osvdb_id(33052, 33053);
 script_name(english:"Multiple IOS IPS Vulnerabilities");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'The Intrusion Prevention System (IPS) feature set of Cisco IOS
contains several vulnerabilities. These include: 

  - Fragmented IP packets may be used to evade
    signature inspection. (CVE-2007-0917)

  - IPS signatures utilizing the regular expression
    feature of the ATOMIC.TCP signature engine may
    cause a router to crash resulting in a denial
    of service. (CVE-2007-0918)'
 );
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?16b1f263");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00807e0a5b.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?8f4c5bae");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070213-iosips."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/13");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/02/13");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCsa53334");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsg15598");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20070213-iosips");
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
else if (version == '12.4(2)XA2')
  security_hole(0);
else if (version == '12.4(2)XA1')
  security_hole(0);
else if (version == '12.4(2)XA')
  security_hole(0);
else if (version == '12.4(11)T')
  security_hole(0);
else if (version == '12.4(9)T2')
  security_hole(0);
else if (version == '12.4(9)T1')
  security_hole(0);
else if (version == '12.4(9)T')
  security_hole(0);
else if (version == '12.4(2)T2')
  security_hole(0);
else if (version == '12.4(2)T1')
  security_hole(0);
else if (version == '12.4(2)T')
  security_hole(0);
else if (version == '12.4(10a)')
  security_hole(0);
else if (version == '12.4(10)')
  security_hole(0);
else if (version == '12.4(8c)')
  security_hole(0);
else if (version == '12.4(8b)')
  security_hole(0);
else if (version == '12.4(8a)')
  security_hole(0);
else if (version == '12.4(8)')
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
else if (version == '12.4(3a)')
  security_hole(0);
else if (version == '12.4(3)')
  security_hole(0);
else if (version == '12.4(1b)')
  security_hole(0);
else if (version == '12.4(1a)')
  security_hole(0);
else if (version == '12.4(1)')
  security_hole(0);
else if (version == '12.3(8)ZA')
  security_hole(0);
else if (version == '12.3(14)YT1')
  security_hole(0);
else if (version == '12.3(14)YT')
  security_hole(0);
else if (version == '12.3(11)YS1')
  security_hole(0);
else if (version == '12.3(11)YS')
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
else if (version == '12.3(14)T3')
  security_hole(0);
else if (version == '12.3(14)T2')
  security_hole(0);
else if (version == '12.3(14)T1')
  security_hole(0);
else if (version == '12.3(14)T')
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
else
  exit(0, 'The host is not affected.');

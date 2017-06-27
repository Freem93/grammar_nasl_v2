#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1691.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48944);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-1999-0160");
 script_bugtraq_id(693);
 script_osvdb_id(1099);
 script_name(english:"Cisco CHAP Authentication Vulnerabilities - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'A serious security vulnerability (bug ID CSCdi91594) exists in PPP CHAP
authentication in all "classic" Cisco IOS software versions (the
software used on Cisco non-switch products with product numbers greater
than or equal to 1000, on the AGS/AGS+/CGS/MGS, and on the CS-500, but
not on Catalyst switches or on 7xx or 9xx routers) starting with the
introduction of CHAP support in release 9.1(1). The vulnerability
permits attackers with appropriate skills and knowledge to completely
circumvent CHAP authentication. Other PPP authentication methods are
not affected. 
A related vulnerability exists in Cisco IOS/700 software (the software
used on 7xx routers). A configuration workaround exists for IOS/700,
and a complete fix for 76x and 77x routers will be included in software
version 4.1(2), due to be released by December, 1997. A fix for 75x
routers is scheduled for the first half of 1998. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-19971001-chap
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?009e80ca");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1691.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?180118a7");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-19971001-chap.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/10/01");
 script_set_attribute(attribute:"patch_publication_date", value: "1997/10/01");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdi91594");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdj37314");
 script_xref(name:"CISCO-SA", value: "cisco-sa-19971001-chap");
 script_summary(english:"IOS version check");
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

# Affected: Cisco IOS 10.3
if (check_release(version: version,
                  patched: make_list("10.3(19a)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: Cisco IOS 11.0
if (check_release(version: version,
                  patched: make_list("11.0(17)", "11.0(17)BT"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: Cisco IOS 11.1
if (check_release(version: version,
                  patched: make_list("11.1(13)", "11.1(13)AA", "11.1(13)CA", "11.1(13)IA"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: Cisco IOS 11.2
if (check_release(version: version,
                  patched: make_list("11.2(4)F1", "11.2(8)", "11.2(8)P"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");

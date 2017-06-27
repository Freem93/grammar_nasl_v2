#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080094e97.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48966);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2002-1706");
 script_bugtraq_id(5041);
 script_osvdb_id(21561);
 script_name(english:"Cable Modem Termination System Authentication Bypass - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'Two issues are described in this security advisory. 
The first issue involves cable modems not manufactured by Cisco that
allow a configuration file to be downloaded from an interface that is
not connected to the network of the cable modem\'s service provider.
This historical behavior allows an unauthorized configuration to be
downloaded to the cable modem. Cisco is providing a feature in its own
software that mitigates this vulnerability. This feature is documented
as CSCdx57688. 
The second issue concerns a vulnerability in Cisco IOS Software on
only the Cisco uBR7200 series and uBR7100 series Universal Broadband
Routers. A defect, documented as CSCdx72740, allows the creation of a
truncated, invalid configuration file that is improperly accepted as
valid by the affected routers. 
Both of these vulnerabilities have been exploited to steal service by
reconfiguring the cable modem to remove bandwidth restrictions.');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020617-cmts-md5-bypass
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?cf56db7e");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080094e97.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?64d3c943");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20020617-cmts-md5-bypass."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/17");
 script_set_attribute(attribute:"patch_publication_date", value: "2002/06/17");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx57688");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx72740");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20020617-cmts-md5-bypass");
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

# Affected: 11.3NA
if (deprecated_version(version, "11.3NA")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 11.3NA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.3T
if (deprecated_version(version, "11.3T")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 11.3T. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.3XA
if (deprecated_version(version, "11.3XA")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 11.3XA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0
if (deprecated_version(version, "12.0")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.0. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0SC
if (deprecated_version(version, "12.0SC")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.0SC. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0T
if (deprecated_version(version, "12.0T")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.0T. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0XR
if (deprecated_version(version, "12.0XR")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.0XR. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1
if (deprecated_version(version, "12.1")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.1. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1CX
if (deprecated_version(version, "12.1CX")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.1CX. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(11b)EC1", "12.1(11.5)EC", "12.1(12)EC"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.1T. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.2
if (deprecated_version(version, "12.2")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.2. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.2BC
if (check_release(version: version,
                  patched: make_list("12.2(8)BC1b", "12.2(8)BC2"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2T
if (deprecated_version(version, "12.2T")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.2T. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.2XF
if (deprecated_version(version, "12.2XF")) {
  security_warning(port:0, extra: '\nNo updates are scheduled for 12.2XF. Upgrade to a supported version\n'); exit(0);
}

exit(0, "The remote host is not affected");

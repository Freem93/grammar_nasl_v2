#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13b6.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48950);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2000-0984");
 script_bugtraq_id(1838);
 script_osvdb_id(6717);
 script_xref(name:"CERT", value:"683677");
 script_name(english:"Cisco IOS HTTP Server Query Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'A defect in multiple releases of Cisco IOS software will cause a Cisco
router or switch to halt and reload if the IOS HTTP service is enabled,
browsing to "http://router-ip/anytext?/" is attempted, and the enable
password is supplied when requested. This defect can be exploited to
produce a denial of service (DoS) attack. 
The vulnerability, identified as Cisco bug ID CSCdr91706, affects
virtually all mainstream Cisco routers and switches running Cisco IOS
software releases 12.0 through 12.1, inclusive. This is not the same
defect as CSCdr36952. 
The vulnerability has been corrected and Cisco is making fixed releases
available for free to replace all affected IOS releases. Customers are
urged to upgrade to releases that are not vulnerable to this defect as
shown in detail below. 
This vulnerability can only be exploited if the enable password is
known or not set. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20001025-ios-http-server-query
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?b2f962f9");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b13b6.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?81828152");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20001025-ios-http-server-query.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2000/10/25");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdr36952");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdr91706");
 script_xref(name:"CISCO-BUG-ID", value:"CSCds57774");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv38391");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20001025-ios-http-server-query");
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

# Affected: 11.2SA
if (version == '11.2SA') {
  security_warning(port:0, extra: '\nNo updates are scheduled for 11.2SA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0T
if (deprecated_version(version, "12.0T")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5) or later\n'); exit(0);
}
# Affected: 12.0W5 (all models)
if (check_release(version: version,
                  patched: make_list("12.0(10)W5(18e)", "12.0(13)W5(19)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5) or later\n'); exit(0);
}
# Affected: 12.0XE
if (deprecated_version(version, "12.0XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(3a)E4 or later\n'); exit(0);
}
# Affected: 12.0XH
if (check_release(version: version,
                  patched: make_list("12.0(4)XH4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XJ
if (check_release(version: version,
                  patched: make_list("12.0(5)XJ6") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(5)"))) {  # listed in the advisory as 12.1(05)
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1AA
if (check_release(version: version,
                  patched: make_list("12.1(5)AA"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DA
if (check_release(version: version,
                  patched: make_list("12.1(4)DA"))) {  # listed in the advisory as 12.01(04)DA
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DB
if (check_release(version: version,
                  patched: make_list("12.1(4)DB"))) {  # listed in the advisory as 12.01(4)DB
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DC
if (check_release(version: version,
                  patched: make_list("12.1(4)DC"))) {  # listed in the advisory as 12.01(4)DC
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(3a)E4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(3a)EC1") )) {  # listed in the advisory as 12.01(03a)EC1
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1T
if (check_release(version: version,
                  patched: make_list("12.1(5)T") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XA
if (deprecated_version(version, "12.1XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5)T or later\n'); exit(0);
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 12.1XB. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5)T or later\n'); exit(0);
}
# Affected: 12.1XD
if (deprecated_version(version, "12.1XD")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5)T or later\n'); exit(0);
}
# Affected: 12.1XE
if (deprecated_version(version, "12.1XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5)T or later\n'); exit(0);
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF2"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XG
if (check_release(version: version,
                  patched: make_list("12.1(3)XG2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5)T or later\n'); exit(0);
}
# Affected: 12.1XI
if (deprecated_version(version, "12.1XI")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 12.1XI. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1XJ
if (deprecated_version(version, "12.1XJ")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 12.1XJ. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1XL
if (deprecated_version(version, "12.1XL")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 12.1XL. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.1XP
if (check_release(version: version,
                  patched: make_list("12.1(3)XP2"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");

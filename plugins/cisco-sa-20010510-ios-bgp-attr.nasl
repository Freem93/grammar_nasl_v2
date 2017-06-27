#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080094a58.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48954);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2001-0650");
 script_bugtraq_id(2733);
 script_osvdb_id(1830);
 script_xref(name:"CERT", value:"106392");
 script_name(english:"Cisco IOS BGP Attribute Corruption Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'A Border Gateway Protocol (BGP) UPDATE contains Network Layer
Reachability Information (NLRI) and attributes that describe the path
to the destination. An unrecognized transitive attribute can cause
failures in Cisco IOS routers, ranging from a crash upon receipt of the
unrecognized transitive attribute, to a later failure upon attempt to
clear the unrecognized transitive attribute. Specific but common
configurations are affected, and described below. The failure was
discovered because of a malfunction in the BGP implementation of
another vendor. There is no workaround. Affected customers are urged to
upgrade to fixed code. 
This vulnerability has been assigned Cisco bug ID CSCdt79947. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010510-ios-bgp-attr
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d7083612");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080094a58.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?fdcf2c80");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20010510-ios-bgp-attr.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/10");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/05/10");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt79947");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20010510-ios-bgp-attr");
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

# Affected: 11.1CA
if (deprecated_version(version, "11.1CA")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 11.1CA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.1CC
if (check_release(version: version,
                  patched: make_list("11.1(36)CC2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CT
if (deprecated_version(version, "11.1CT")) {
 security_warning(port:0, extra: '\nUpgrade to 12.0ST\n'); exit(0);
}
# Affected: 11.2
if (deprecated_version(version, "11.2")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 11.2. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.2BC
if (deprecated_version(version, "11.2BC")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1(8) or later\n'); exit(0);
}
# Affected: 11.2F
if (deprecated_version(version, "11.2F")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 11.2F. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.2GS
if (deprecated_version(version, "11.2GS")) {
 security_warning(port:0, extra: '\nUpgrade to 12.0(17)S or later\n'); exit(0);
}
# Affected: 11.2P
if (deprecated_version(version, "11.2P")) {
 security_warning(port:0, extra: '\nUpgrade to 12.0(17) or later\n'); exit(0);
}
# Affected: 11.2(4)XA
if (version == '11.2(4)XA') {
 security_warning(port:0, extra: '\nNo updates are scheduled for 11.2(4)XA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.2(9)XA
if (version == '11.2(9)XA') {
 security_warning(port:0, extra: '\nNo updates are scheduled for 11.2(9)XA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.3
if (deprecated_version(version, "11.3")) {
 security_warning(port:0, extra: '\nUpgrade to 12.0(17) or later\n'); exit(0);
}
# Affected: 11.3AA
if (deprecated_version(version, "11.3AA")) {
 security_warning(port:0, extra: '\nUpgrade to 12.0(17) or later\n'); exit(0);
}
# Affected: 11.3DA
if (deprecated_version(version, "11.3DA")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1DA\n'); exit(0);
}
# Affected: 11.3DB
if (deprecated_version(version, "11.3DB")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1DB\n'); exit(0);
}
# Affected: 11.3HA
if (deprecated_version(version, "11.3HA")) {
 security_warning(port:0, extra: '\nUpgrade to 12.0(17) or later\n'); exit(0);
}
# Affected: 11.3MA
if (deprecated_version(version, "11.3MA")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 11.3MA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.3NA
if (deprecated_version(version, "11.3NA")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 11.3T
if (deprecated_version(version, "11.3T")) {
 security_warning(port:0, extra: '\nUpgrade to 12.0(17) or later\n'); exit(0);
}
# Affected: 11.3WA4
#if (deprecated_version(version, "11.3WA4")) {
# security_warning(port:0, extra: '\nNo updates are scheduled for 11.3WA4. Upgrade to a supported version\n'); exit(0);
#}
# Affected: 11.3(2)XA
if (version == '11.3(2)XA') {
 security_warning(port:0, extra: '\nNo updates are scheduled for 11.3(2)XA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(17)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0DA
if (deprecated_version(version, "12.0DA")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1DA\n'); exit(0);
}
# Affected: 12.0DB
if (deprecated_version(version, "12.0DB")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1DB\n'); exit(0);
}
# Affected: 12.0DC
if (deprecated_version(version, "12.0DC")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1DC\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(15)S3", "12.0(16)S1"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0T
if (check_release(version: version,
                  patched: make_list("12.0(5)T") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0W5
if (
  version =~ 'W5' &&  # avoid flagging things like W4 (if such a thing exists)
  check_release(version: version, patched: make_list("12.0(10)W5(18g)", "12.0(16)W5(21)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 12.0XC
if (deprecated_version(version, "12.0XC")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 12.0XD
if (deprecated_version(version, "12.0XD")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 12.0XF
if (deprecated_version(version, "12.0XF")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 12.0XG
if (deprecated_version(version, "12.0XG")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 12.0XH
if (deprecated_version(version, "12.0XH")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 12.0XI
if (deprecated_version(version, "12.0XI")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}
# Affected: 12.0XJ
if (deprecated_version(version, "12.0XJ")) {
 security_warning(port:0, extra: '\nUpgrade to 12.1\n'); exit(0);
}

exit(0, "The remote host is not affected");

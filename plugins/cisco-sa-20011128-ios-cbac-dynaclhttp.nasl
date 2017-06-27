#TRUSTED 0f177e9427d0d57b7e18a03b5bdd7b2088e6527966c354bc1daa93c4863cf7cfa06e9145e74d4f4a8754e044654d952f1ca98d22d073dc546ac599bf2a563c74b313b2bb3eb0fa28797582d804226eb8470e3c4e91a66eb2d2622d138ff287efc327a22bcdfbcde6508b1da03f2f4fe2db4c87a3bfcc692d455d1851ce1e9d79418c919c6f45559bdce22511bf76951f0c0b567b8f05ceaaf7cb12e97e5fa2841a37262968fc91f686374eda491c5ce935dd10ed807f7367c6d5226621cc295eab6b6d91ff5eb32bca690cdffd8a0c052839c51f69a0c31ef30f7af13b7ee80203b547201e6d2fd22badb1add77004bf23abc62e47eeab81c3b10ef2cd2a9f78347233526b2c6d45d58be887f992f6fc7673ad6d0831d571bb483c8e5f48d5fbae9961f305487d1bcbeb2ea425406930edb2731303088ab8929223ffab4928ddba95676fa7e6695304f4aa757eb7b56f002554e2120f23441fcd6b601fa2835b503c639bc7bdc90ac59b6147f2d66ce52a01c60fd04bcca50b6980486daacb5b1d6edd8c146260ff7e213a800ff297fd8ab9ce111f046c3ae83bbf8e65fa453290b92614178ab983024eac3bdad5e53e516ce6eba52a564634715b7332edaa5e1e69d261f1d43173b0b28d81f40fe7e0d7065f517c5231bccc5fab14766d98b238eee7e8e2f8e90a78039075a840fde9e3810fd4ed9863ee3e2b6c3e86a56565
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800941ee.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48962);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2001-0929");
 script_bugtraq_id(3588);
 script_osvdb_id(808);
 script_xref(name:"CERT", value:"362483");
 script_name(english:"A Vulnerability in IOS Firewall Feature Set - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'The IOS Firewall Feature set, also known as Cisco Secure Integrated
Software, also known as Context Based Access Control (CBAC), and
introduced in IOS version 11.2P, has a vulnerability that permits
traffic normally expected to be denied by the dynamic access control
lists.
This vulnerability is documented as Cisco Bug ID CSCdv48261.
No other Cisco product is vulnerable.
There is no workaround.
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011128-ios-cbac-dynacl
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7b48f6d");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800941ee.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?0c0a0348");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20011128-ios-cbac-dynacl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/11/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv48261");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20011128-ios-cbac-dynacl");
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
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Affected: 11.2P
if (deprecated_version(version, "11.2P")) {
 report_extra = '\nUpdate to 12.0(20.3) or later\n'; flag++;
}
# Affected: 11.3T
if (deprecated_version(version, "11.3T")) {
 report_extra = '\nUpdate to 12.0(20.3) or later\n'; flag++;
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(20.3)", "12.0(21)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0T
if (deprecated_version(version, "12.0T")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XC
if (deprecated_version(version, "12.0XC")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XD
if (deprecated_version(version, "12.0XD")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XE
if (deprecated_version(version, "12.0XE")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XG
if (deprecated_version(version, "12.0XG")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XI
if (deprecated_version(version, "12.0XI")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XK
if (deprecated_version(version, "12.0XK")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XM
if (deprecated_version(version, "12.0XM")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XQ
if (deprecated_version(version, "12.0XQ")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XR
if (deprecated_version(version, "12.0XR")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.0XV
if (deprecated_version(version, "12.0XV")) {
 report_extra = '\nUpdate to 12.1(11a) or later\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(11a)", "12.1(11.1)", "12.1(12)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8a)E5", "12.1(9.6)E", "12.1(10)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 report_extra = '\nUpdate to 12.1(5)YB1 or later\n'; flag++;
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XG
if (check_release(version: version,
                  patched: make_list("12.1(3)XG6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XI")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XJ")) {
 report_extra = '\nUpdate to 12.1(5)YB or later\n'; flag++;
}
if (deprecated_version(version, "12.1XK")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XL")) {
 report_extra = '\nUpdate to 12.2(5)7 or later\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1XP")) {
 report_extra = '\nUpdate to 12.2(5)T7 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XT")) {
 report_extra = '\nUpdate to 12.2(5)T7 or later\n'; flag++;
}
# Affected: 12.1YB
if (check_release(version: version,
                  patched: make_list("12.1(5)YB5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YC
if (check_release(version: version,
                  patched: make_list("12.1(5)YC2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YE
if (check_release(version: version,
                  patched: make_list("12.1(5)YE4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YF
if (check_release(version: version,
                  patched: make_list("12.1(5)YF3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(5.7)", "12.2(6)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2DD")) {
 report_extra = '\nUpdate to 12.2(4)B or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(5.7)T", "12.2(8)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XD
if (check_release(version: version,
                  patched: make_list("12.2(2)XD3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XE
if (check_release(version: version,
                  patched: make_list("12.2(1)XE2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XH
if (check_release(version: version,
                  patched: make_list("12.2(2)XH2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XI
if (check_release(version: version,
                  patched: make_list("12.2(2)XI1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XJ
if (check_release(version: version,
                  patched: make_list("12.2(2)XJ1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XK
if (check_release(version: version,
                  patched: make_list("12.2(2)XK5") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XQ
if (check_release(version: version,
                  patched: make_list("12.2(2)XQ2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip\s+inspect\s+", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1396.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48953);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2001-0288");
 script_bugtraq_id(2682);
 script_osvdb_id(199);
 script_xref(name:"CERT", value:"498440");
 script_name(english:"Cisco IOS Software TCP Initial Sequence Number Randomization Improvements - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'Cisco IOS Software contains a flaw that permits the successful
prediction of TCP Initial Sequence Numbers. 
This vulnerability is present in all released versions of Cisco IOS
software running on Cisco routers and switches. It only affects the
security of TCP connections that originate or terminate on the affected
Cisco device itself; it does not apply to TCP traffic forwarded through
the affected device in transit between two other hosts. 
To remove the vulnerability, Cisco is offering free software upgrades
for all affected platforms. The defect is described in DDTS record
CSCds04747.
 Workarounds are available that limit or deny successful exploitation
of the vulnerability by filtering traffic containing forged IP source
addresses at the perimeter of a network or directly on individual
devices. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010301-ios-tcp-isn-random
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?021e980a");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1396.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?733b0267");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20010301-ios-tcp-isn-random.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/03/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/03/01");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCds04747");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20010301-ios-tcp-isn-random");
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

# Affected: 11.0
if (deprecated_version(version, "11.0")) {
 security_hole(port:0, extra: '\nUpdate to 11.1(22a) or later\n'); exit(0);
}
# Affected: 11.1
if (check_release(version: version,
                  patched: make_list("11.1(24a)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1AA
if (deprecated_version(version, "11.1AA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 11.1CA
if (check_release(version: version,
                  patched: make_list("11.1(36)CA1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CC
if (check_release(version: version,
                  patched: make_list("11.1(36)CC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CT
if (deprecated_version(version, "11.1CT")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(11)ST2 or later\n'); exit(0);
}
# Affected: 11.1IA
if (check_release(version: version,
                  patched: make_list("11.1(28a)IA1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2
if (check_release(version: version,
                  patched: make_list("11.2(25)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2BC
if (deprecated_version(version, "11.2BC")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 11.2F
if (deprecated_version(version, "11.2F")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 11.2F. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.2GS
if (deprecated_version(version, "11.2GS")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(15)S1 or later\n'); exit(0);
}
# Affected: 11.2P
if (check_release(version: version,
                  patched: make_list("11.2(25)P"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2SA
if (deprecated_version(version, "11.2SA")) {
 security_hole(port:0, extra: '\nUpgrade to 12.0WC\n'); exit(0);
}
# Affected: 11.2WA3
if (version == '11.2WA3') {
 security_hole(port:0, extra: '\nUpdate to 12.0(10)W(18b) or later\n'); exit(0);
}
# Affected: 11.2(4)XA
if (version == '11.2(4)XA' || version == '11.2(9)XA') {
 security_hole(port:0, extra: '\nUpdate to 11.2(25)P or later\n'); exit(0);
}
# Affected: 11.3
if (check_release(version: version,
                  patched: make_list("11.3(11b)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3AA
if (check_release(version: version,
                  patched: make_list("11.3(11a)AA") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3DA
if (deprecated_version(version, "11.3DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)DA1 or later\n'); exit(0);
}
# Affected: 11.3DB
if (deprecated_version(version, "11.3DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(4)DB1 or later\n'); exit(0);
}
# Affected: 11.3HA
if (deprecated_version(version, "11.3HA")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 11.3HA. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.3MA
if (check_release(version: version,
                  patched: make_list("11.3(1)MA8") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3NA
if (deprecated_version(version, "11.3NA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 11.3T
if (check_release(version: version,
                  patched: make_list("11.3(11b)T1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3WA4
if (version == '11.3WA4') {
 security_hole(port:0, extra: '\nUpdate to 12.0(10)W(18b) or later\n'); exit(0);
}
# Affected: 11.3(2)XA
if (version == '11.3(2)XA') {
 security_hole(port:0, extra: '\nUpdate to 11.3(11b)T1 or later\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(15)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(14)S1", "12.0(14.6)S") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0DA
if (deprecated_version(version, "12.0DA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)DA1 or later\n'); exit(0);
}
# Affected: 12.0DB
if (deprecated_version(version, "12.0DB")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(4)DB1 or later\n'); exit(0);
}
# Affected: 12.0DC
if (deprecated_version(version, "12.0DC")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(4)DA2 or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(14)S1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SC
if (check_release(version: version,
                  patched: make_list("12.0(15)SC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SL
if (check_release(version: version,
                  patched: make_list("12.0(14)SL1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(11)ST2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SX
if (deprecated_version(version, "12.0SX")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(5c)E8 or later\n'); exit(0);
}
# Affected: 12.0T
if (deprecated_version(version, "12.0T")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0W5
if (check_release(version: version,
                  patched: make_list("12.0(13)W5(19c)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WT
if (check_release(version: version,
                  patched: make_list("12.0(13)WT6(1)") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XC
if (deprecated_version(version, "12.0XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XD
if (deprecated_version(version, "12.0XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XE
if (deprecated_version(version, "12.0XE")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)E8 or later\n'); exit(0);
}
# Affected: 12.0XF
if (deprecated_version(version, "12.0XF")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XG
if (deprecated_version(version, "12.0XG")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XH
if (check_release(version: version,
                  patched: make_list("12.0(4)XH5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XI
if (deprecated_version(version, "12.0XI")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XJ
if (deprecated_version(version, "12.0XJ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XK
if (check_release(version: version,
                  patched: make_list("12.0(7)XK4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XL
if (deprecated_version(version, "12.0XL")) {
 security_hole(port:0, extra: '\nUpdate to 12.0(4)XH5 or later\n'); exit(0);
}
# Affected: 12.0XM
if (check_release(version: version,
                  patched: make_list("12.0(5)XM1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XN
if (deprecated_version(version, "12.0XN")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 12.0XN. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0XP
if (deprecated_version(version, "12.0XP")) {
 security_hole(port:0, extra: '\nUpdate to 12.1WC\n'); exit(0);
}
# Affected: 12.0XQ
if (deprecated_version(version, "12.0XQ")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XR
if (deprecated_version(version, "12.0XR")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.0XS
if (deprecated_version(version, "12.0XS")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)E8 or later\n'); exit(0);
}
# Affected: 12.0XU
if (deprecated_version(version, "12.0XU")) {
 security_hole(port:0, extra: '\nUpdate to 12.1WC\n'); exit(0);
}
# Affected: 12.0XV
if (deprecated_version(version, "12.0XV")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(5c)"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1AA
if (check_release(version: version,
                  patched: make_list("12.1(7)AA"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DA
if (check_release(version: version,
                  patched: make_list("12.1(5)DA1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1CX
if (check_release(version: version,
                  patched: make_list("12.1(4)CX"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DB
if (check_release(version: version,
                  patched: make_list("12.1(4)DB1"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DC
if (check_release(version: version,
                  patched: make_list("12.1(4)DC2"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(5.6)E"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(4.5)EC"))) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EX
if (check_release(version: version,
                  patched: make_list("12.1(5c)EX") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1T
if (check_release(version: version,
                  patched: make_list("12.1(5)T5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XA
if (deprecated_version(version, "12.1XA")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.1XD
if (deprecated_version(version, "12.1XD")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.1XE
if (deprecated_version(version, "12.1XE")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XG
if (check_release(version: version,
                  patched: make_list("12.1(3)XG3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XH
if (check_release(version: version,
                  patched: make_list("12.1(2)XH5") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XI
if (check_release(version: version,
                  patched: make_list("12.1(3a)XI6") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XJ
if (deprecated_version(version, "12.1XJ")) {
 security_hole(port:0, extra: '\nNo updates are scheduled for 12.1XJ. Upgrade to a supported version.\n'); exit(0);
}
# Affected: 12.1XK
if (deprecated_version(version, "12.1XK")) {
 security_hole(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.1XL
if (check_release(version: version,
                  patched: make_list("12.1(3)XL1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XP
if (check_release(version: version,
                  patched: make_list("12.1(3)XP3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XQ
if (check_release(version: version,
                  patched: make_list("12.1(3)XQ3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XR
if (check_release(version: version,
                  patched: make_list("12.1(5)XR1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XS
if (check_release(version: version,
                  patched: make_list("12.1(5)XS") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XT
if (check_release(version: version,
                  patched: make_list("12.1(3)XT1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XU
if (check_release(version: version,
                  patched: make_list("12.1(5)XU1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XV
if (check_release(version: version,
                  patched: make_list("12.1(5)XV1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XW
if (check_release(version: version,
                  patched: make_list("12.1(5)XW2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XX
if (check_release(version: version,
                  patched: make_list("12.1(5)XX3") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XY
if (check_release(version: version,
                  patched: make_list("12.1(5)XY4") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XZ
if (check_release(version: version,
                  patched: make_list("12.1(5)XZ2") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YA
if (check_release(version: version,
                  patched: make_list("12.1(5)YA1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YB
if (check_release(version: version,
                  patched: make_list("12.1(5)YB") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YC
if (check_release(version: version,
                  patched: make_list("12.1(5)YC1") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YD
if (check_release(version: version,
                  patched: make_list("12.1(5)YD") )) {
 security_hole(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");

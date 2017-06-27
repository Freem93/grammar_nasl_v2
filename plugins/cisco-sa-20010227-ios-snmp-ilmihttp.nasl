#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/csa/cisco-sa-20010227-ios-snmp-ilmi.html

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48951);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2001-0711");
 script_bugtraq_id(2427);
 script_osvdb_id(8820);
 script_xref(name:"CERT", value:"976280");
 script_name(english:"Cisco IOS Software SNMP Read-Write ILMI Community String Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'Cisco IOS Software releases based on versions 11.x and 12.0 contain a
defect that allows a limited number of SNMP objects to be viewed and
modified without authorization using a undocumented ILMI community
string. Some of the modifiable objects are confined to the MIB-II
system group, such as "sysContact", "sysLocation", and "sysName", that
do not affect the device\'s normal operation but that may cause
confusion if modified unexpectedly. The remaining objects are contained
in the LAN-EMULATION-CLIENT and PNNI MIBs, and modification of those
objects may affect ATM configuration. An affected device might be
vulnerable to a denial of service attack if it is not protected against
unauthorized use of the ILMI community string.
The vulnerability is only present in certain combinations of IOS
releases on Cisco routers and switches. ILMI is a necessary component
for ATM, and the vulnerability is present in every IOS release that
contains the supporting software for ATM and ILMI without regard to the
actual presence of an ATM interface or the physical ability of the
device to support an ATM connection. 
To remove this vulnerability, Cisco is offering free software upgrades
for all affected platforms. The defect is documented in DDTS record
CSCdp11863. 
In lieu of a software upgrade, a workaround can be applied to certain
IOS releases by disabling the ILMI community or "*ilmi" view and
applying an access list to prevent unauthorized access to SNMP. Any
affected system, regardless of software release, may be protected by
filtering SNMP traffic at a network perimeter or on individual devices. ');
 # http://www.cisco.com/en/US/products/csa/cisco-sa-20010227-ios-snmp-ilmi.html
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?2aaae497");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20010227-ios-snmp-ilmi.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/27");
 script_set_attribute(attribute:"patch_publication_date", value: "2000/10/27");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdp11863");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20010227-ios-snmp-ilmi");
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

# Affected: 11.0
if (check_release(version: version,
                  patched: make_list("11.0(22a)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1
if (check_release(version: version,
                  patched: make_list("11.1(24a)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1AA
if (deprecated_version(version, "11.1AA")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 11.1CA
if (check_release(version: version,
                  patched: make_list("11.1(36)CA1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CC
if (check_release(version: version,
                  patched: make_list("11.1(36)CC1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.1CT
if (deprecated_version(version, "11.1CT")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(11)ST2 or later\n'); exit(0);
}
# Affected: 11.1IA
if (check_release(version: version,
                  patched: make_list("11.1(28)IA1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2
if (check_release(version: version,
                  patched: make_list("11.2(25a)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2BC
if (deprecated_version(version, "11.2BC")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 11.2GS
if (deprecated_version(version, "11.2GS")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(15)S1 or later\n'); exit(0);
}
# Affected: 11.2P
if (check_release(version: version,
                  patched: make_list("11.2(25a)P") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2SA
if (deprecated_version(version, "11.2SA")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(5)WC or later\n'); exit(0);
}
# Affected: 11.2WA3, 11.3WA4
if (version == '11.2WA3' || version == '11.3WA4') {
 security_warning(port:0, extra: '\nUpdate to 12.0(10)W(18b) or later\n'); exit(0);
}
# Affected: 11.2(4)XA, 11.2(9)XA
if (version == '11.2(4)XA' || version == '11.2(9)XA') {
 security_warning(port:0, extra: '\nUpdate to 11.2(25a)P or later\n'); exit(0);
}
# Affected: 11.3
if (deprecated_version(version, "11.3")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 11.3. Upgrade to a supported version\n'); exit(0);
}
# Affected: 11.3AA
if (check_release(version: version,
                  patched: make_list("11.3(11a)AA") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3DA
if (deprecated_version(version, "11.3DA")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5)DA1 or later\n'); exit(0);
}
# Affected: 11.3DB
if (deprecated_version(version, "11.3DB")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(4)DB1 or later\n'); exit(0);
}
# Affected: 11.3MA
if (check_release(version: version,
                  patched: make_list("11.3(1)MA8") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3NA
if (deprecated_version(version, "11.3NA")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 11.3T
if (check_release(version: version,
                  patched: make_list("11.3(11b)T1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(7.1)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0DA
if (deprecated_version(version, "12.0DA")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(7.1)T or later\n'); exit(0);
}
# Affected: 12.0DB
if (deprecated_version(version, "12.0DB")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(4)DB1 or later\n'); exit(0);
}
# Affected: 12.0DC
if (deprecated_version(version, "12.0DC")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(4)DC2 or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(15)S1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SC
if (check_release(version: version,
                  patched: make_list("12.0(15)SC") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SL
if (check_release(version: version,
                  patched: make_list("12.0(14)SL1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(11)ST2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0T
if (deprecated_version(version, "12.0T")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0W5
if (check_release(version: version,
                  patched: make_list("12.0(10)W5(18b)") )) {  # the lowest version of all maintenance versions listed for 12.0W5
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WT
if (check_release(version: version,
                  patched: make_list("12.0(13)WT6(1)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XC
if (deprecated_version(version, "12.0XC")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XD
if (deprecated_version(version, "12.0XD")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XE
if (deprecated_version(version, "12.0XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5c)E8 or later\n'); exit(0);
}
# Affected: 12.0XF
if (deprecated_version(version, "12.0XF")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XG
if (deprecated_version(version, "12.0XG")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XH
if (check_release(version: version,
                  patched: make_list("12.0(4)XH5") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XI
if (deprecated_version(version, "12.0XI")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XJ
if (deprecated_version(version, "12.0XJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XK
if (check_release(version: version,
                  patched: make_list("12.0(7)XK4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XL
if (deprecated_version(version, "12.0XL")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(4)XH5 or later\n'); exit(0);
}
# Affected: 12.0XM
if (deprecated_version(version, "12.0XM")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XN
if (deprecated_version(version, "12.0XN")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 12.0XN. Upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0XQ
if (deprecated_version(version, "12.0XQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(7) or later\n'); exit(0);
}
# Affected: 12.0XR
if (deprecated_version(version, "12.0XR")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}
# Affected: 12.0XS
if (deprecated_version(version, "12.0XS")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5c)E8 or later\n'); exit(0);
}
# Affected: 12.0XV
if (deprecated_version(version, "12.0XV")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(5)T5 or later\n'); exit(0);
}

exit(0, "The remote host is not affected");

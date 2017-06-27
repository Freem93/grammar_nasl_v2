#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b113c.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48961);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2001-0895");
 script_bugtraq_id(3547);
 script_osvdb_id(807);
 script_xref(name:"CERT", value:"399355");
 script_name(english:"Cisco IOS ARP Table Overwrite Vulnerability - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'It is possible to send an Address Resolution Protocol (ARP) packet on a
local broadcast interface (for example, Ethernet, cable, Token Ring,
FDDI) which could cause a router or switch running specific versions of
Cisco IOS Software Release to stop sending and receiving ARP packets
on the local router interface. This will in a short time cause the
router and local hosts to be unable to send packets to each other. ARP
packets received by the router for the router\'s own interface address
but a different Media Access Control (MAC) address will overwrite the
router\'s MAC address in the ARP table with the one from the received
ARP packet. This was demonstrated to attendees of the Black Hat
conference and should be considered to be public knowledge. This attack
is only successful against devices on the segment local to the attacker
or attacking host. 
This vulnerability is documented in Cisco Bug ID CSCdu81936, and a
workaround is available. 
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011115-ios-arp-overwrite
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?fb24d347");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b113c.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?cc4073eb");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory 
cisco-sa-20011115-ios-arp-overwrite.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/15");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/11/15");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu81936");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu85209");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv04366");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv63206");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv77220");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv77242");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv83509");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20011115-ios-arp-overwrite");
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

# Affected: 11.1 and earlier, all variants
if (
  version =~ "^[0-9]\." ||     # 0.x-9.x
  version =~ "^10\." ||        # 10.x
  version =~ "^11\.[01][^0-9]" # 11.0, 11.1
)
{
 security_warning(port:0, extra: '\nNo updates are scheduled for versions 11.1 and earlier. Upgrade to a supported version\n'); exit(0);
}

# the language for all 11.2 and 11.3 releases are ambiguous, e.g.,
#   11.2: Not affected after 11.2(13)
# talked to Cisco and they said this means 11.2(13) is the first non-vulnerable version

# Affected: 11.2
if (check_release(version: version,
                  patched: make_list("11.2(13)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.2P
if (check_release(version: version,
                  patched: make_list("11.2(12)P") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3
if (check_release(version: version,
                  patched: make_list("11.3(3)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 11.3T
if (deprecated_version(version, "11.3T")) {
 security_warning(port:0, extra: '\nUpdate to 11.3(3) or later\n'); exit(0);
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(19.6)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0DA
if (deprecated_version(version, "12.0DA")) {
 security_warning(port:0, extra: '\nUpgrade to 12.2DA\n'); exit(0);
}
# Affected: 12.0DB
if (deprecated_version(version, "12.0DB")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4.2) or later\n'); exit(0);  # the advisory says to upgrade to 12.1T, but for 12.1T it says to upgrade to 12.2 (which says to upgrade to 12.2(4.2)
}
# Affected: 12.0DC
if (deprecated_version(version, "12.0DC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(2)B or later\n'); exit(0);
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(21)S") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0SC
if (deprecated_version(version, "12.0SC")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(8.5)EC or later\n'); exit(0);
}
# Affected: 12.0SL
if (deprecated_version(version, "12.0SL")) {
 security_warning(port:0, extra: '\nUpdate to 12.0(20)ST or later\n'); exit(0);
}
# Affected: 12.0SP
if (check_release(version: version,
                  patched: make_list("12.0(20)SP") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(20)ST") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0T
if (deprecated_version(version, "12.0T")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0W5
if (
  version =~ 'W5' && # avoid flagging versions like W4, if such a thing exists
  check_release(version: version, patched: make_list("12.0(16)W5(21b)", "12.0(18)W5(22a)", "12.0(20)W5(24)") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5)WC3") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.0XA
if (deprecated_version(version, "12.0XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XB
if (deprecated_version(version, "12.0XB")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XC
if (deprecated_version(version, "12.0XC")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XD
if (deprecated_version(version, "12.0XD")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XE
if (deprecated_version(version, "12.0XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11)E or later\n'); exit(0);
}
# Affected: 12.0XF
if (deprecated_version(version, "12.0XF")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XG
if (deprecated_version(version, "12.0XG")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XH
if (deprecated_version(version, "12.0XH")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XI
if (deprecated_version(version, "12.0XI")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XJ
if (deprecated_version(version, "12.0XJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XK
if (deprecated_version(version, "12.0XK")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XL
if (deprecated_version(version, "12.0XL")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XM
if (deprecated_version(version, "12.0XM")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XN
if (deprecated_version(version, "12.0XN")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XP
if (deprecated_version(version, "12.0XP")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 12.0XP. Use the workaround or upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0XQ
if (deprecated_version(version, "12.0XQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XR
if (deprecated_version(version, "12.0XR")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.0XS
if (deprecated_version(version, "12.0XS")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11)E or later\n'); exit(0);
}
# Affected: 12.0XU
if (deprecated_version(version, "12.0XU")) {
 security_warning(port:0, extra: '\nNo updates are scheduled for 12.0XU. Use the workaround or upgrade to a supported version\n'); exit(0);
}
# Affected: 12.0XV
if (deprecated_version(version, "12.0XV")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(10.3)", "12.1(11)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1AA
if (check_release(version: version,
                  patched: make_list("12.1(10)AA") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1DA
if (deprecated_version(version, "12.1DA")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(7)T or later\n'); exit(0);
}
# Affected: 12.1DB
if (deprecated_version(version, "12.1DB")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(2)B or later\n'); exit(0);
}
# Affected: 12.1DC
if (deprecated_version(version, "12.1DC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(2)B or later\n'); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8a)E5") )) {  # advisory lists this as 12.1(08a)E05
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(6)EA1a") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(8.5)EC", "12.1(9)EC"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1EX
if (deprecated_version(version, "12.1EX")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11)E or later\n'); exit(0);
}
# Affected: 12.1EZ
if (check_release(version: version,
                  patched: make_list("12.1(6)EZ4"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XA
if (deprecated_version(version, "12.1XA")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XD
if (deprecated_version(version, "12.1XD")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XE
if (deprecated_version(version, "12.1XE")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF5") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XG
if (check_release(version: version,
                  patched: make_list("12.1(3)XG6") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XI
if (deprecated_version(version, "12.1XI")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XJ
if (deprecated_version(version, "12.1XJ")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XK
if (deprecated_version(version, "12.1XK")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XL
if (deprecated_version(version, "12.1XL")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(4)2 or later\n'); exit(0);
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM6") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1XP
if (deprecated_version(version, "12.1XP")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(2)T or later\n'); exit(0);
}
# Affected: 12.1XQ
if (deprecated_version(version, "12.1XQ")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(2)T or later\n'); exit(0);
}
# Affected: 12.1XR
if (deprecated_version(version, "12.1XR")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(7)T or later\n'); exit(0);
}
# Affected: 12.1XS
if (deprecated_version(version, "12.1XS")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(2)XC1 or later\n'); exit(0);
}
# Affected: 12.1XT
if (deprecated_version(version, "12.1XT")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(7)T or later\n'); exit(0);
}
# Affected: 12.1XV
if (deprecated_version(version, "12.1XV")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(2)XB2 or later\n'); exit(0);
}
# Affected: 12.1XW
if (deprecated_version(version, "12.1XW")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.1XX
if (deprecated_version(version, "12.1XX")) {
 security_warning(port:0, extra: '\nUpdate to 12.1(11) or later\n'); exit(0);
}
# Affected: 12.1YA
if (deprecated_version(version, "12.1YA")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(2)XB or later\n'); exit(0);
}
# Affected: 12.1YB
if (check_release(version: version,
                  patched: make_list("12.1(5)YB5") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YC
if (check_release(version: version,
                  patched: make_list("12.1(5)YC2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YD
if (deprecated_version(version, "12.1YD")) {
 security_warning(port:0, extra: '\nUpdate to 12.2(7)T or later\n'); exit(0);
}
# Affected: 12.1YE
if (check_release(version: version,
                  patched: make_list("12.1(5)YE4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.1YF
if (check_release(version: version,
                  patched: make_list("12.1(5)YF3") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(4.2)", "12.2(5)"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2DD
if (check_release(version: version,
                  patched: make_list("12.2(2)DD1"))) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(7)T") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XA
if (check_release(version: version,
                  patched: make_list("12.2(2)XA4") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XB
if (check_release(version: version,
                  patched: make_list("12.2(2)XB2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XC
if (check_release(version: version,
                  patched: make_list("12.2(2)XC1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XD
if (check_release(version: version,
                  patched: make_list("12.2(1)XD3") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XE
if (check_release(version: version,
                  patched: make_list("12.2(1)XE2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XG
if (check_release(version: version,
                  patched: make_list("12.2(2)XG1") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XH
if (check_release(version: version,
                  patched: make_list("12.2(2)XH2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XJ
if (check_release(version: version,
                  patched: make_list("12.2(2)XJ2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XK
if (check_release(version: version,
                  patched: make_list("12.2(2)XK5") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}
# Affected: 12.2XQ
if (check_release(version: version,
                  patched: make_list("12.2(2)XQ2") )) {
 security_warning(port:0, extra: '\nUpdate to ' + patch_update + ' or later\n'); exit(0);
}

exit(0, "The remote host is not affected");

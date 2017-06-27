#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/csa/cisco-sa-20050629-aaa.html
#
# @DEPRECATED@
#
# Disabled on 2011/12/07. Deprecated by cisco-sa-20050629-aaa.nasl

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(55424);
 script_version("$Revision: 1.5 $");
 script_name(english:"RADIUS Authentication Bypass - Cisco Systems");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch." );
 script_set_attribute(attribute:"description", value:
'Remote Authentication Dial In User Service (RADIUS) authentication on a
device that is running certain versions of Cisco Internetworking
Operating System (IOS) and configured with a fallback method to none
can be bypassed.
Systems that are configured for other authentication methods or that
are not configured with a fallback method to none are not affected.
Only the systems that are running certain versions of Cisco IOS are
affected. Not all configurations using RADIUS and none are vulnerable
to this issue. Some configurations using RADIUS, none and an additional
method are not affected.
Cisco has made free software available to address this vulnerability.
There are workarounds available to mitigate the effects of the
vulnerability. 
The vulnerabilities are documented as the following Cisco Bug IDs:
');
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?b981b4d9");
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?f5408145");
 script_set_attribute(attribute:"solution", value: "Apply the described patch (see plugin output).");
 script_set_attribute(attribute:"risk_factor", value: "High");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/27");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCee45312");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20050629-aaa");
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2011-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

exit(0, "This plugin has been deprecated. Use cisco-sa-20050629-aaa.nasl (plugin ID 48986) instead");

include("cisco_func.inc");

#

version = get_kb_item("Host/Cisco/IOS/Version");
if ( ! version ) exit(0);

if (deprecated_version(version, "12.2B")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2BC")) {
 security_hole(0, extra: "Migrate to 12.3(13)BC or later"); exit(0);
}
if (deprecated_version(version, "12.2BW")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2BX")) {
 security_hole(0, extra: "Migrate to 12.3(7)XI6 or later"); exit(0);
}
if (deprecated_version(version, "12.2BY")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2BZ")) {
 security_hole(0, extra: "Migrate to 12.3(7)XI6 or later"); exit(0);
}
if (deprecated_version(version, "12.2CX")) {
 security_hole(0, extra: "Migrate to 12.3(13)BC or later"); exit(0);
}
if (deprecated_version(version, "12.2CY")) {
 security_hole(0, extra: "Migrate to 12.3(13)BC or later"); exit(0);
}
if (deprecated_version(version, "12.2EW")) {
 security_hole(0, extra: "Migrate to 12.2(25)EWA2 or later"); exit(0);
}
# Affected: 12.2EWA
if (check_release(version: version,
                  patched: make_list("12.2(25)EWA2") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2EY
if (check_release(version: version,
                  patched: make_list("12.2(25)EY2") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2EZ")) {
 security_hole(0, extra: "Migrate to 12.2(25)SEC or later"); exit(0);
}
if (deprecated_version(version, "12.2JA")) {
 security_hole(0, extra: "Migrate to 12.3(7)JA or later"); exit(0);
}
if (deprecated_version(version, "12.2MB")) {
 security_hole(0, extra: "Migrate to 12.2SW or later"); exit(0);
}
if (deprecated_version(version, "12.2MC")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2MX")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
# Affected: 12.2SE
if (check_release(version: version,
                  patched: make_list("12.2(25)SEB2"),
                  newest: "12.2(25)SEC" )) {
 security_hole(0, extra: "Update to 12.2(25)SEC or later"); exit(0);
}
# Affected: 12.2SXD
if (check_release(version: version,
                  patched: make_list("12.2(18)SXD5") )) {
 security_hole(0); exit(0);
}
# Affected: 12.2SXE
if (check_release(version: version,
                  patched: make_list("12.2(18)SXE2") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.2T")) {
 security_hole(0, extra: "Migrate to 12.3 or later"); exit(0);
}
if (deprecated_version(version, "12.2XB")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XC")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2XD")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XE")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XF")) {
 security_hole(0, extra: "Migrate to 12.3(13)BC or later"); exit(0);
}
if (deprecated_version(version, "12.2XG")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XH")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XI")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XJ")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XK")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XL")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XM")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XQ")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XR/12.2(2)XR/12.2(4)XR")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2(15)XR")) {
 security_hole(0, extra: "Migrate to 12.3(7)JA or later"); exit(0);
}
if (deprecated_version(version, "12.2XT")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2XW")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YB")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YC")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YD")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YF")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YG")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YH")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YJ")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YL")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YM")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YN")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YP")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YQ")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YR")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YT")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2YU")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YV")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YW")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2YY")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2ZB")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2ZC")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2ZD")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2ZE")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2ZF")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2ZG")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2ZJ")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2ZN")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.2ZO")) {
 security_hole(0, extra: "Migrate to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.2ZP")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
# Affected: 12.3
if (check_release(version: version,
                  newest: "12.3(10)" )) {
 security_hole(0, extra: "Update to 12.3(10) or later"); exit(0);
}
if (deprecated_version(version, "12.3B")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
# Affected: 12.3BC
if (check_release(version: version,
                  newest: "12.3(13)BC" )) {
 security_hole(0, extra: "Update to 12.3(13)BC or later"); exit(0);
}
if (deprecated_version(version, "12.3BW")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
# Affected: 12.3JA
if (check_release(version: version,
                  patched: make_list("12.3(7)JA") )) {
 security_hole(0); exit(0);
}
# Affected: 12.3T
if (check_release(version: version,
                  patched: make_list("12.3(7)T11"),
                  newest: "12.3(11)" )) {
 security_hole(0, extra: "Update to 12.3(11) or later"); exit(0);
}
if (deprecated_version(version, "12.3XA")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XB")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XD")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XE")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XF")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XG")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XH")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
# Affected: 12.3XI
if (check_release(version: version,
                  patched: make_list("12.3(7)XI6") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3XJ")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XK")) {
 security_hole(0, extra: "Migrate to 12.3(14)T or later"); exit(0);
}
# Affected: 12.3XL
if (check_release(version: version,
                  newest: "12.3(11)XL" )) {
 security_hole(0, extra: "Update to 12.3(11)XL or later"); exit(0);
}
if (deprecated_version(version, "12.3XM")) {
 security_hole(0, extra: "Migrate to 12.3(14)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XN")) {
 security_hole(0, extra: "Migrate to 12.3(14)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XQ")) {
 security_hole(0, extra: "Migrate to 12.3(14)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XS")) {
 security_hole(0, extra: "Migrate to 12.3(14)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XW")) {
 security_hole(0, extra: "Migrate to 12.3(11)T or later"); exit(0);
}
if (deprecated_version(version, "12.3XX")) {
 security_hole(0, extra: "Migrate to 12.3(14)T or later"); exit(0);
}
# Affected: 12.3XY
if (check_release(version: version,
                  patched: make_list("12.3(8)XY5") )) {
 security_hole(0); exit(0);
}
if (deprecated_version(version, "12.3YA")) {
 security_hole(0, extra: "Migrate to 12.3(14)T or later"); exit(0);
}
# Affected: 12.3YD
if (check_release(version: version,
                  newest: "12.3(8)YD" )) {
 security_hole(0, extra: "Update to 12.3(8)YD or later"); exit(0);
}
# Affected: 12.3YF
if (check_release(version: version,
                  newest: "12.3(11)YF" )) {
 security_hole(0, extra: "Update to 12.3(11)YF or later"); exit(0);
}
# Affected: 12.3YG
if (check_release(version: version,
                  newest: "12.3(8)YG" )) {
 security_hole(0, extra: "Update to 12.3(8)YG or later"); exit(0);
}
# Affected: 12.3YH
if (check_release(version: version,
                  newest: "12.3(8)YH" )) {
 security_hole(0, extra: "Update to 12.3(8)YH or later"); exit(0);
}
# Affected: 12.3YI
if (check_release(version: version,
                  newest: "12.3(8)YI" )) {
 security_hole(0, extra: "Update to 12.3(8)YI or later"); exit(0);
}
# Affected: 12.3YJ
if (check_release(version: version,
                  newest: "12.3(11)YJ" )) {
 security_hole(0, extra: "Update to 12.3(11)YJ or later"); exit(0);
}
# Affected: 12.3YK
if (check_release(version: version,
                  newest: "12.3(11)YK" )) {
 security_hole(0, extra: "Update to 12.3(11)YK or later"); exit(0);
}
# Affected: 12.3YL
if (check_release(version: version,
                  newest: "12.3(11)YL" )) {
 security_hole(0, extra: "Update to 12.3(11)YL or later"); exit(0);
}
# Affected: 12.3YN
if (check_release(version: version,
                  newest: "12.3(11)YN" )) {
 security_hole(0, extra: "Update to 12.3(11)YN or later"); exit(0);
}
# Affected: 12.3YR
if (check_release(version: version,
                  newest: "12.3(11)YR" )) {
 security_hole(0, extra: "Update to 12.3(11)YR or later"); exit(0);
}
# Affected: 12.3YS
if (check_release(version: version,
                  newest: "12.3(11)YS" )) {
 security_hole(0, extra: "Update to 12.3(11)YS or later"); exit(0);
}
# Affected: 12.3YQ
if (check_release(version: version,
                  newest: "12.3(14)YQ" )) {
 security_hole(0, extra: "Update to 12.3(14)YQ or later"); exit(0);
}
# Affected: 12.4
if (check_release(version: version,
                  newest: "12.4(1)" )) {
 security_hole(0, extra: "Update to 12.4(1) or later"); exit(0);
}

exit(0, "The remote host is not affected");

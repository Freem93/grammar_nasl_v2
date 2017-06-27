#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/csa/cisco-sa-20030515-saa.html
#
# @DEPRECATED@
#
# Disabled on 2011/12/06. Deprecated by cisco-sa-20030515-saahttp.nasl

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48970);
 script_version("$Revision: 1.8 $");
 script_name(english:"Cisco IOS Software Processing of SAA Packets - Cisco Systems (Deprecated)");
 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
'The Service Assurance Agent (SAA) is the new name for the Response Time
Reporter (RTR) feature.
The router is vulnerable only if the RTR responder is enabled. When the
router receives a malformed RTR packet, it will crash. RTR is disabled
by default. Although RTR was introduced in Cisco IOS Software Release
11.2, only the following main releases are vulnerable:
For the complete list please see the Software Versions and Fixes
section.
No other Cisco product is vulnerable.
There is no workaround short of disabling the RTR responder. It is
possible to mitigate the vulnerability by applying the access control
list (ACL) on the router.
');
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?7e84eef2");
 script_set_attribute(attribute:"see_also", value: "http://www.cisco.com/en/US/products/csa/cisco-sa-20030515-saa.html");
 script_set_attribute(attribute:"solution", value: "Apply the described patch (see plugin output).");
 script_set_attribute(attribute:"risk_factor", value: "High");
 script_set_attribute(attribute:"plugin_type", value: "local");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/09/01");
 script_cvs_date("$Date: 2014/08/11 19:30:34 $");
 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx17916");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx61997");
 script_xref(name:"CISCO-SA", value: "cisco-sa-20030515-saa");
 script_summary(english:"Uses SNMP to determine if a flaw is present");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

exit(0, "This plugin has been deprecated. Use cisco-sa-20030515-saahttp.nasl (plugin ID 55385) instead");

include("cisco_func.inc");

#

version = get_kb_item("Host/Cisco/IOS/Version");
if ( ! version ) exit(0);

# Affected: 12.0SY
if (check_release(version: version,
                  patched: make_list("12.0(22)SY"),
                  newest: "12.0(22)SY" )) {
 security_hole(0, extra: "Update to 12.0(22)SY or later"); exit(0);
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(18)"),
                  newest: "12.1(18)" )) {
 security_hole(0, extra: "Update to 12.1(18) or later"); exit(0);
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(13)E"),
                  newest: "12.1(13)E" )) {
 security_hole(0, extra: "Update to 12.1(13)E or later"); exit(0);
}
# Affected: 12.1EW
if (check_release(version: version,
                  patched: make_list("12.1(11b)EW"),
                  newest: "12.1(11b)EW" )) {
 security_hole(0, extra: "Update to 12.1(11b)EW or later"); exit(0);
}
# Affected: 12.1EW
if (check_release(version: version,
                  patched: make_list("12.1(11b)EW(0.46)"),
                  newest: "12.1(11b)EW(0.46)" )) {
 security_hole(0, extra: "Update to 12.1(11b)EW(0.46) or later"); exit(0);
}
# Affected: 12.1EX
if (check_release(version: version,
                  patched: make_list("12.1(11b)EX"),
                  newest: "12.1(11b)EX" )) {
 security_hole(0, extra: "Update to 12.1(11b)EX or later"); exit(0);
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(10)"),
                  newest: "12.2(10)" )) {
 security_hole(0, extra: "Update to 12.2(10) or later"); exit(0);
}
# Affected: 12.2BZ
if (check_release(version: version,
                  patched: make_list("12.2(15)BZ"),
                  newest: "12.2(15)BZ" )) {
 security_hole(0, extra: "Update to 12.2(15)BZ or later"); exit(0);
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(12)DA"),
                  newest: "12.2(12)DA" )) {
 security_hole(0, extra: "Update to 12.2(12)DA or later"); exit(0);
}
# Affected: 12.2XK
if (check_release(version: version,
                  patched: make_list("12.2(2)XK3"),
                  newest: "12.2(2)XK3" )) {
 security_hole(0, extra: "Update to 12.2(2)XK3 or later"); exit(0);
}
# Affected: 12.2XL
if (check_release(version: version,
                  patched: make_list("12.2(4)XL5"),
                  newest: "12.2(4)XL5" )) {
 security_hole(0, extra: "Update to 12.2(4)XL5 or later"); exit(0);
}
# Affected: 12.2YG
if (check_release(version: version,
                  patched: make_list("12.2(4)YG"),
                  newest: "12.2(4)YG" )) {
 security_hole(0, extra: "Update to 12.2(4)YG or later"); exit(0);
}
# Affected: 12.2YH
if (check_release(version: version,
                  patched: make_list("12.2(4)YH"),
                  newest: "12.2(4)YH" )) {
 security_hole(0, extra: "Update to 12.2(4)YH or later"); exit(0);
}

exit(0, "The remote host is not affected");

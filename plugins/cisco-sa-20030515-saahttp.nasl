#TRUSTED b183fb37b4ee1535e95406ebd2283b72161fffcbec83a326e3382a8212f40f3d93dda5ef7720de8544975a67708c2539d09d2455d5ccd8d28a996bcb8a4fc43cdcda4177d478bb96aece914d3cbb03978ebbd1f95161eb5891e727ae28eb4170c27db992977520cd7278e466965f505c5ad7bdc4db39662ac3509798f3729fbe8e3e6b2ab708ce292d463cce74ce61f18d2882b68ba32c4cf676b7198698d837a7158fe45bcf6fdd5e99a49178f70e0e3ea8a086dce867946fbe8baad5dc04babc0a35238f02075faf0e753e5ba3b0845ec84a27af6457eb33e128f9bfac30fa6f0b3d15f171cf5370537617bd2bdd2b7f5e50c8fc9baf70b8e6515ab362a94b27d3bf88a635e605c03e47069855b1ec89f660de7017536f2e73751d44e302ef37fd94134d211d532b40eb1dff939d48292291f9a47dff32be664378ed6cd438f6d23a7fa8855714a18ff93bcbd11655f0395d2f194f0bfb32fb33b7244ed44376531bdd3aac3b09fe0751e1887b05a5e15945d03a6bd6b6411de88941b34e6ec06322c9cb47ca5c394bf7535550174aa9dc340714e1ab70be07128b1cbdfaf2aa45ed64f28fee70f95267f05f7ed955b88235860d2f0836f9252a2e7a68931bf3699ebcfe9b2369ca0bc3e0571e9dc179fcbf72bb38f857e647276738eb6acfa2d63e4bb64fe933246d008dd1983ca86969bc6d7c3740cc57df77e2501a9b33
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a008017ba10.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(55385);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2003-0305");
 script_bugtraq_id(7607);
 script_osvdb_id(8902);
 script_name(english:"Cisco IOS Software Processing of SAA Packets - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'The Service Assurance Agent (SAA) is the new name for the Response Time
Reporter (RTR) feature.
The router is vulnerable only if the RTR responder is enabled. When the
router receives a malformed RTR packet, it will crash. RTR is disabled
by default.
There is no workaround short of disabling the RTR responder. It is
possible to mitigate the vulnerability by applying the access control
list (ACL) on the router.
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20030515-saa
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e84eef2");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a008017ba10.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?edd86ded");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20030515-saa.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/05/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/22");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx17916");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx61997");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20030515-saa");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2011-2014 Tenable Network Security, Inc.");
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

# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(21)S3", "12.0(21.03)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SC
if (deprecated_version(version, "12.0SC")) {
 report_extra = '\nNo fix is available for 12.0SC releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0SL
if (deprecated_version(version, "12.0SL")) {
 report_extra = '\nNo fix is available for 12.0SL releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0SP
if (check_release(version: version,
                  patched: make_list("12.0(20)SP3", "12.0(20.04)SP2"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(19)ST5", "12.0(21)ST2"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0SX
if (deprecated_version(version, "12.0SX")) {
 report_extra = '\nNo fix is available for 12.0SX releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.0SY
if (check_release(version: version,
                  patched: make_list("12.0(21.03)SY", "12.0(22)SY"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0WC
if (check_release(version: version,
                  patched: make_list("12.0(5)WCa"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0XE")) {
 report_extra = '\nNo fix is available for 12.0XE releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(18)", "12.1(18.1)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(12.5)E", "12.1(13)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(8)EA1c"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(12c)EC"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EW
if (check_release(version: version,
                  patched: make_list("12.1(11b)EW", "12.1(11b)EW(0.46)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EX
if (check_release(version: version,
                  patched: make_list("12.1(11b)EX"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XF
if (deprecated_version(version, "12.1XF")) {
 report_extra = '\nUpdate to 12.1(5)T or later\n'; flag++;
}
# Affected: 12.1XG
if (deprecated_version(version, "12.1XG")) {
 report_extra = '\nUpdate to 12.1(1)T or later\n'; flag++;
}
# Affected: 12.1YB
if (deprecated_version(version, "12.1YB")) {
 report_extra = '\nUpdate to 12.1(2)T or later\n'; flag++;
}
# Affected: 12.1YC
if (deprecated_version(version, "12.1YC")) {
 report_extra = '\nUpdate to 12.1(4)T or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(10)", "12.2(10.4)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(4)B
if (version == "12.2(4)B") {
 report_extra = '\nUpdate to 12.2(13.3)B or later\n'; flag++;
}
# Affected: 12.2BC
if (deprecated_version(version, "12.2BC")) {
 report_extra = '\nNo fix is available for 12.2BC releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2BY
if (deprecated_version(version, "12.2BY")) {
 report_extra = '\nUpdate to 12.2(13.3)B or later\n'; flag++;
}
# Affected: 12.2BZ
if (check_release(version: version,
                  patched: make_list("12.2(15)BZ"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2DA
if (check_release(version: version,
                  patched: make_list("12.2(11.4)DA", "12.2(12)DA"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2MB
if (check_release(version: version,
                  patched: make_list("12.2(4)MB5"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(11.1)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XC
if (check_release(version: version,
                  patched: make_list("12.2(1a)XC5"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XD
if (deprecated_version(version, "12.2XD")) {
 report_extra = '\nUpdate to 12.2(8)YN or later\n'; flag++;
}
# Affected: 12.2XE
if (deprecated_version(version, "12.2XE")) {
 report_extra = '\nUpdate to 12.2(8)T or later\n'; flag++;
}
# Affected: 12.2XH
if (deprecated_version(version, "12.2XH")) {
 report_extra = '\nUpdate to 12.2(8)T or later\n'; flag++;
}
# Affected: 12.2XI
if (deprecated_version(version, "12.2XI")) {
 report_extra = '\nUpdate to 12.2(12)T or later\n'; flag++;
}
# Affected: 12.2XJ
if (deprecated_version(version, "12.2XJ")) {
 report_extra = '\nUpdate to 12.2(4)YB or later\n'; flag++;
}
# Affected: 12.2XK
if (check_release(version: version,
                  patched: make_list("12.2(2)XK3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XL
if (check_release(version: version,
                  patched: make_list("12.2(4)XL5"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XM
if (deprecated_version(version, "12.2XM")) {
 report_extra = '\nUpdate to 12.2(8)YB or later\n'; flag++;
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2YB
if (check_release(version: version,
                  patched: make_list("12.2(8)YB"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2YC
if (check_release(version: version,
                  patched: make_list("12.2(4)YC4"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2YF
if (deprecated_version(version, "12.2YF")) {
 report_extra = '\nNo fix is available for 12.2YF releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2YG
if (check_release(version: version,
                  patched: make_list("12.2(4)YG"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2YH
if (check_release(version: version,
                  patched: make_list("12.2(4)YH"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show rtr responder", "show rtr responder");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"RTR\s+Responder\s+is:\s+Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

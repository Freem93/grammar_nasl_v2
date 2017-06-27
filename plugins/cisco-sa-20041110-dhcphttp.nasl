#TRUSTED 742a131f698f2c682e24cc09e69cd59133371241166bca2641122d3d7354ad0b2b4c87d8d8a334aea36a1f25f17661b4a37eb5b350a87e1be9bc6c06015ed9315051a617bf28f495fa55fdb0b1de1b35a9467074b77a0dc898e8b110c0725ff761af174df0bddb2caa10d748045ade60a946f9aee5a9e13394563e80d2ea1e5591126c5e114ae1e35ea443e000d9a23d653aa5eb835fc5c78679d932eae561d48d213f371f7abda18cc4a92651c1031e11186d403bb176edbc21dd908b6012d04873c0a0ae4f6498c5b627e1daf5e1fbaaeaf66f18c840d872fceda892e5d16f9eb9e9265ab8c28a18509dd28a0fce7fa541f4220f9c851aa8fff16f57fc518e633b770712d7ce8f66073b8fd0834c9612e7de5672c17fed7dcb33c2fcf1f4cc36811c585d856de4a003a863274536b44b724975a088c17761e6b4cd52430dcbca609652366008e1cb2f4c79798f3f63a441eb79f601028bde2c242803e2589db3c85fb96f91289df5fed1493a9bd888abc618944e64583e45c78e758935460212859311c261c50dac23deb07e2069b92482cfcd0ff4f153e4b8988ca12d886143f3f698169c20d02773ff1c4d306144e9d73895547220c955422b339b4a8143835475963d9722011168aeeac70c9b9826cb5ceadf19d8a51bfee3befe8aae0e2d4b98096bf22c135eaadbfadf003ca7e1ea1e378dbaaf415d104700c9b33a9b
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00803448c7.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48978);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2004-1111");
 script_osvdb_id(11605);
 script_xref(name:"CERT", value:"630104");
 script_name(english:"Cisco IOS DHCP Blocked Interface Denial-of-Service - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Cisco IOS devices running branches of Cisco IOS version 12.2S that
have Dynamic Host Configuration Protocol (DHCP) server or relay agent
enabled, even if not configured, are vulnerable to a denial of service
where the input queue becomes blocked when receiving specifically
crafted DHCP packets. Cisco is providing free fixed software to address
this issue. There are also workarounds to mitigate this vulnerability.
This issue was introduced by the fix included in CSCdx46180 and is
being tracked by Cisco Bug ID CSCee50294.'
 );
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20041110-dhcp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f0d4f1a");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00803448c7.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?ccad8deb");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20041110-dhcp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/11/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx46180");
 script_xref(name:"CISCO-BUG-ID", value:"CSCee50294");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20041110-dhcp");
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

# Affected: 12.2(18)EW
if (check_release(version: version,
                  patched: make_list("12.2(18)EW2"),
                  oldest: "12.2(18)EW")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(20)EW
if (version =~ "^12\.2\(20\)EW[0-9]*$") {
 report_extra = '\nUpdate to 12.2(20)EWA or later\n'; flag++;
}
# Affected: 12.2(18)EWA
if (check_release(version: version,
                  patched: make_list("12.2(20)EWA"),
                  oldest: "12.2(18)EWA")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(18)S
if (check_release(version: version,
                  patched: make_list("12.2(18)S6"),
                  oldest: "12.2(18)S")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(18)SE
if (check_release(version: version,
                  patched: make_list("12.2(20)SE3"),
                  oldest: "12.2(18)SE")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(18)SV
if (check_release(version: version,
                  patched: make_list("12.2(24)SV"),
                  oldest: "12.2(18)SV")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(18)SW
if (check_release(version: version,
                  patched: make_list("12.2(25)SW"),
                  oldest: "12.2(18)SW")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(14)SZ
if (version =~ "^12\.2\(14\)SZ[0-9]*$") {
 report_extra = '\nUpdate to 12.2(20)S4 or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (!preg(pattern:"no\s+service\s+dhcp", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

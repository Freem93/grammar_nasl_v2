#TRUSTED 433c56ad520541bb4c0bdb232f181100fc9a5f5b30d614573663902145a4a01d57659c872a9727c335705707599d07da8a6f0738438739f734d55a16e12ab54f7946aff952ec9bc194c3f4de052b9c94f7701a48ffd051a5ce2632ad9d7f8fe7cfabe10940b57cba8fd5da653864fb06bba0ef29090d13fddada271aaa0b0b9bdef8b88143f9e181a28ac29cb3fcedebda807dd1192cfe323c5ed6c3ed57533cee33a44680c65c94d21f9387d4031c550b541212c578928bca9643d4d4595559fc99d9d5960c1bfe2f6e3bfe0b2d132620a565abdb7d17b8e806febd5738a9e077fd5586be1031a3a7d8fcbc0b11477fb632281b8383d858e9c3d6c31399df6f8bcf3dc8d3adc8d624e7b7f89efc3d99e87256962095b4f33654f4d278b20f5fdd417d299bbc3dc70e7c82a6b1db7b895c033616adbf50133b57bb12df03919e0abfc11412f61486f61cf76de5eb8d3c1f626fec91030a82299d40c9c4519e9a0fc192e703fb2b94936b3a6b4aad3b28de79abf2d08ecfad743fd4b72223ac2ab59802c0dabb5434d3bb2c3a1cbe0e2a8d4637eec26029c0e7b9a0cf709dc7f8f5193e0a4df9b7dea2e5714e3876d5f673d9abab01a1c237159e1a71122aefa38e4eaf3016897565ff948eb85c9d6916b2d3ca82d7932606218dc0e85d1fa80664ec21e917c054b2668c128d87db0f8df10854cdc818951526b12b9087213b7c
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b168e.shtml

include("compat.inc");

if (description)
{
 script_id(48957);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/05");

 script_cve_id("CVE-2001-0572");
 script_osvdb_id(3561, 3562);
 script_xref(name:"CERT", value:"596827");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt55357");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt57231");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt72996");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt73353");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt96253");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu37371");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv34668");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv34676");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdv34679");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20010627-ssh");

 script_name(english:"Multiple SSH Vulnerabilities - Cisco Systems");
 script_summary(english:"Checks the IOS version.");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Four different Cisco product lines are susceptible to multiple
vulnerabilities discovered in the Secure Shell (SSH) protocol version
1.5. These issues have been addressed, and fixes have been integrated
into the Cisco products that support this protocol.
By exploiting the weakness in the SSH protocol, it is possible to
insert arbitrary commands into an established SSH session, collect
information that may help in brute-force key recovery, or brute force a
session key.
Affected product lines are:
No other Cisco products are vulnerable. It is possible to mitigate this
vulnerability by preventing, or having control over, the interception
of SSH traffic.
Cisco IOS is not vulnerable to any of known exploits that are currently
used to compromise UNIX hosts. For the warning regarding increased
scanning activity for hosts running SSH consult CERT/CC.');
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/articles/SSH-Traffic-Analysis");
 script_set_attribute(attribute:"see_also", value: "http://seclists.org/bugtraq/2001/Mar/262");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010627-ssh
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?cf3fc1b5");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b168e.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?ea4df78e");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20010627-ssh.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/06/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2016 Tenable Network Security, Inc.");
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
                  patched: make_list("12.0(20)S") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1DB
if (deprecated_version(version, "12.1DB")) {
 report_extra = '\nNo updates are scheduled for 12.1DB. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1DC
if (deprecated_version(version, "12.1DC")) {
 report_extra = '\nNo updates are scheduled for 12.1DC. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8a)E") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(6.5)EC3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EX
if (deprecated_version(version, "12.1EX")) {
 report_extra = '\nUpdate to 12.1(8a)E or later\n'; flag++;
}
# Affected: 12.1EY
if (check_release(version: version,
                  patched: make_list("12.1(6)EY") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EZ
if (check_release(version: version,
                  patched: make_list("12.1(6)EZ2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XA
if (deprecated_version(version, "12.1XA")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XB
if (deprecated_version(version, "12.1XB")) {
 report_extra = '\nNo updates are scheduled for 12.1XB. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1XC
if (deprecated_version(version, "12.1XC")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XD
if (deprecated_version(version, "12.1XD")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XE
if (deprecated_version(version, "12.1XE")) {
 report_extra = '\nNo updates are scheduled for 12.1XE. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.1XF
if (check_release(version: version,
                  patched: make_list("12.1(2)XF4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XG
if (deprecated_version(version, "12.1XG")) {
 report_extra = '\nUpdate to 12.1(2)XF4 or later\n'; flag++;
}
# Affected: 12.1XH
if (deprecated_version(version, "12.1XH")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XI
if (deprecated_version(version, "12.1XI")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XJ
if (deprecated_version(version, "12.1XJ")) {
 report_extra = '\nUpdate to 12.1(5)YB4 or later\n'; flag++;
}
# Affected: 12.1XL
if (deprecated_version(version, "12.1XL")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(4)XM4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XP
if (check_release(version: version,
                  patched: make_list("12.1(3)XP4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XQ
if (deprecated_version(version, "12.1XQ")) {
 report_extra = '\nUpdate to 12.2(1b) or later\n'; flag++;
}
# Affected: 12.1XR
if (check_release(version: version,
                  patched: make_list("12.1(5)XR2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XS
if (check_release(version: version,
                  patched: make_list("12.1(5)XS2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XT
if (check_release(version: version,
                  patched: make_list("12.1(3)XT3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XU
if (check_release(version: version,
                  patched: make_list("12.1(5)XU1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XV
if (check_release(version: version,
                  patched: make_list("12.1(5)XV3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XY
if (check_release(version: version,
                  patched: make_list("12.1(5)XY6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YA
if (deprecated_version(version, "12.1YA")) {
 report_extra = '\nUpdate to 12.2(2)XB or later\n'; flag++;
}
# Affected: 12.1YB
if (check_release(version: version,
                  patched: make_list("12.1(5)YB4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YC
if (check_release(version: version,
                  patched: make_list("12.1(5)YC1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YD
if (check_release(version: version,
                  patched: make_list("12.1(5)YD2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1YF
if (check_release(version: version,
                  patched: make_list("12.1(5)YF2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(1.1)", "12.2(1b)", "12.2(3)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(2.2)T") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XA
if (check_release(version: version,
                  patched: make_list("12.2(2)XA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XD
if (check_release(version: version,
                  patched: make_list("12.2(1)XD1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XE
if (check_release(version: version,
                  patched: make_list("12.2(1)XE") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XH
if (check_release(version: version,
                  patched: make_list("12.2(1)XH") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2XQ
if (check_release(version: version,
                  patched: make_list("12.2(1)XQ") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"version\s+1\.5", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#TRUSTED 5a38810eb16976b14e137fcc072fd676f8fff53c463b73f0fc42766913e9e64b5cbb9a1d00fc08b31db39b40458fc1da4712f20eff60a20540d7fb6eb5bfc0abe8287951c4c5947ee2096ebb2dbadb580afb68f4a4a0171a44fa514402f256492895a6fab18efb9ce92a6ad1723137c9c6d2325d2ed2ca91db10d48a8e363bf31836c6ef175fdf78c01f1b098759ebfe4fdced2a1535111f103083af4aa6fe7f7a2e7bb0c8c79d240f0df1972e1e7a01ed0487b74575f993783127195d8d71622d04011a5bd081e74919a90257de2b40831a23bc9da567dc2475a5d29f109ad3fc219a4bc6516e076b0c0ed2475a3a9f8d5c7e0cdfc1e8d498e036fbecffc010487c05ae8f49366686e9d7a404123b357f966d88e4cf88c4ffc4cda233e9469a3dbd84caa8e0bdceb9a00b3481b065480b0491cd4b3efc29bca6bb744b48e89c648caf6fa1906204c86c3a2db63195adf1e1be1385898ac29a342c02339ae70c69c67a419ffcbe8c19b3ca30fa6800fdde51e2339a5231f5a8d387b122f839fd5c493ee88fd8bdb6f3e04e10d7daffd72cff6d6ee5bb5aa44c66f030fd945971d080386b574b6b4140f0ca22191c440e44da41afc7f460d16d0798f12871c2ae30fe45d923cc05ecb0445bb03348e2029fefe6b3b6d4738070c7026937dcc8d70dad94b81ceab42ff344740281b0d21f351218dcabdfa0da8931f7167a5809b6
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00801ea156.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48972);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/12");
 script_cve_id("CVE-2004-0054");
 script_bugtraq_id(9406);
 script_xref(name:"CERT-CC", value:"749342");
 script_xref(name:"CERT-CC", value:"CA-2004-01");
 script_name(english:"Vulnerabilities in H.323 Message Processing - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Multiple Cisco products contain vulnerabilities in the processing of
H.323 messages, which are typically used in Voice over Internet
Protocol (VoIP) or multimedia applications. A test suite has been
developed by the University of Oulu to target this protocol and
identify vulnerabilities.
Support for the H.323 protocol was introduced in Cisco IOS Software
Release 11.3T. Release 11.3T, and all later Cisco IOS releases may be
affected if the software includes support for voice/multimedia
applications. Vulnerable devices include those that contain software
support for H.323 as network elements as well as those configured for
IOS Network Address Translation (NAT) and those configured for IOS
Firewall (also known as Context-Based Access Control [CBAC]).
 Other Cisco voice products that do not run Cisco IOS may also be
affected.
These vulnerabilities can be exploited repeatedly to produce a denial
of service (DoS).
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20040113-h323
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?767c198a");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00801ea156.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?3b4f7afb");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040113-h323.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/01/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdr48143");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt09262");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt54401");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdw14262");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx40184");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx76632");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx77253");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx82831");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea19885");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea27536");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea32240");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea33065");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea36231");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea42527");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea42826");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea44227");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea44309");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea46231");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea46342");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea46545");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea48726");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea48755");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea51030");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea51076");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea54851");
 script_xref(name:"CISCO-BUG-ID", value:"CSCea55518");
 script_xref(name:"CISCO-BUG-ID", value:"CSCec76694");
 script_xref(name:"CISCO-BUG-ID", value:"CSCec76776");
 script_xref(name:"CISCO-BUG-ID", value:"CSCec77152");
 script_xref(name:"CISCO-BUG-ID", value:"CSCec79541");
 script_xref(name:"CISCO-BUG-ID", value:"CSCec87533");
 script_xref(name:"CISCO-BUG-ID", value:"CSCed28873");
 script_xref(name:"CISCO-BUG-ID", value:"CSCef42352");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20040113-h323");
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

# Introduced H.323 feature in 11.3(3)T
if (deprecated_version(version, "11.3T") &&
    !check_release(version: version, patched: make_list("11.3(3)T"))) {
 report_extra = '\nUpdate to 12.0(27) or later\n'; flag++;
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(28)", "12.0(27)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(23)S3", "12.0(24)S2", "12.0(25)S1", "12.0(26)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0ST")) {
 report_extra = '\nNo fixes are planned for 12.0ST releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0T")) {
 report_extra = '\nNo fixes are planned for 12.0T releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.0XC")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XD")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XG")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XH")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XI")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XJ")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XK")) {
 report_extra = '\nUpdate to 12.2(19)b or later\n'; flag++;
}
if (deprecated_version(version, "12.0XL")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XN")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XQ")) {
 report_extra = '\nUpdate to 12.1(22) or later\n'; flag++;
}
if (deprecated_version(version, "12.0XR")) {
 report_extra = '\nUpdate to 12.2(19)b or later\n'; flag++;
}
if (deprecated_version(version, "12.0XT")) {
 report_extra = '\nNo fixes are planned for 12.0XT releases. Upgrade to a supported release\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(22)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1AA")) {
 report_extra = '\nUpdate to 12.2(19)b or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(13)E12", "12.1(20)E2", "12.1(8b)E16", "12.1(11b)E14", "12.1(14)E9", "12.1(19)E6"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1EC")) {
 report_extra = '\nNo fixes are planned for 12.1EC releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.1EZ")) {
 report_extra = '\nNo fixes are planned for 12.1EZ releases. Upgrade to a supported release\n'; flag++;
}
# Affected: 12.1T
if (check_release(version: version,
                  patched: make_list("12.1(5)T17"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.1XA")) {
 report_extra = '\nUpdate to 12.2(19)b or later\n'; flag++;
}
if (deprecated_version(version, "12.1XB")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XC")) {
 report_extra = '\nUpdate to 12.2(19)b or later\n'; flag++;
}
if (deprecated_version(version, "12.1XD")) {
 report_extra = '\nUpdate to 12.2(19)b or later\n'; flag++;
}
if (deprecated_version(version, "12.1XG")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XH")) {
 report_extra = '\nUpdate to 12.2(19)b or later\n'; flag++;
}
if (deprecated_version(version, "12.1XI")) {
 report_extra = '\nUpdate to 12.2(19)b or later\n'; flag++;
}
if (deprecated_version(version, "12.1XJ")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XL")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XM")) {
 report_extra = '\nUpdate to 12.2(2)XB15 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XP")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XQ")) {
 report_extra = '\nUpdate to 12.2(2)XB15 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XR")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XT")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XU")) {
 report_extra = '\nUpdate to 12.2(4)T6 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XV")) {
 report_extra = '\nUpdate to 12.2(2)XB15 or later\n'; flag++;
}
if (deprecated_version(version, "12.1XW")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YB")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YC")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YD")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YE")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YF")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YH")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.1YI")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(10g)", "12.2(13c)", "12.2(13e)", "12.2(16a)", "12.2(16f)", "12.2(17d)", "12.2(19b)", "12.2(21a)", "12.2(17)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2B")) {
 report_extra = '\nUpdate to 12.3(4)T1 or later\n'; flag++;
}
if (deprecated_version(version, "12.2BW")) {
 report_extra = '\nUpdate to 12.2(15)T5 / 12.3(3e) or later\n'; flag++;
}
if (deprecated_version(version, "12.2BX")) {
 report_extra = '\nNo fixes are planned for 12.2BX releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2DD")) {
 report_extra = '\nUpdate to 12.3(3e) or later\n'; flag++;
}
if (deprecated_version(version, "12.2DX")) {
 report_extra = '\nUpdate to 12.3(3e) or later\n'; flag++;
}
if (deprecated_version(version, "12.2MC")) {
 report_extra = '\nNo fixes are planned for 12.2MC releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2MX")) {
 report_extra = '\nUpdate to 12.3(4)T1 or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S3", "12.2(18)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SX
if (check_release(version: version,
                  patched: make_list("12.2(17a)SXA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SY
if (check_release(version: version,
                  patched: make_list("12.2(14)SY3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(11)T8", "12.2(13)T3", "12.2(15)T2", "12.2(4)T6", "12.2(8)T10"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2XA")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
# Affected: 12.2XB
if (check_release(version: version,
                  patched: make_list("12.2(2)XB14"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2XC")) {
 report_extra = '\nUpdate to 12.3(3e) or later\n'; flag++;
}
if (deprecated_version(version, "12.2XD")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XG")) {
 report_extra = '\nUpdate to 12.2(8)T10 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XH")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XI")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XJ")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XK")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XL")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XM")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XN")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XQ")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XS")) {
 report_extra = '\nUpdate to 12.2(2)XB15 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XT")) {
 report_extra = '\nUpdate to 12.2(11)T9 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XU")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2XW")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
# Affected: 12.2YA
if (check_release(version: version,
                  patched: make_list("12.2(4)YA7"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2YB")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YC")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YD")) {
 report_extra = '\nUpdate to 12.3(2)T3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YE")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YF")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YH")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YJ")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YK")) {
 report_extra = '\nUpdate to 12.2(13)ZC or later\n'; flag++;
}
if (deprecated_version(version, "12.2YL")) {
 report_extra = '\nUpdate to 12.3(2)T3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YM")) {
 report_extra = '\nUpdate to 12.3(2)T3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YN")) {
 report_extra = '\nUpdate to 12.3(2)T3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YT")) {
 report_extra = '\nUpdate to 12.2(15)T5 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YU")) {
 report_extra = '\nUpdate to 12.3(4)T1 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YV")) {
 report_extra = '\nUpdate to 12.3(4)T1 or later\n'; flag++;
}
# Affected: 12.2YW
if (check_release(version: version,
                  patched: make_list("12.2(8)YW3"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.2YX")) {
 report_extra = '\nUpdate to 12.2(S) Release 3 / 12.2(14)SU or later\n'; flag++;
}
if (deprecated_version(version, "12.2YY")) {
 report_extra = '\nUpdate to 12.3(2)T3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2YZ")) {
 report_extra = '\nNo fixes are planned for 12.2YZ releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2ZB")) {
 report_extra = '\nUpdate to 12.3(2)T3 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZC")) {
 report_extra = '\nNo fixes are planned for 12.2ZC releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2ZD")) {
 report_extra = '\nNo fixes are planned for 12.2ZD releases. Upgrade to a supported release\n'; flag++;
}
if (deprecated_version(version, "12.2ZE")) {
 report_extra = '\nUpdate to 12.3(3e) or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZF")) {
 report_extra = '\nUpdate to 12.2(15)SL1 or later\n'; flag++;
}
if (deprecated_version(version, "12.2ZG")) {
 report_extra = '\nNo fixes are planned for 12.2ZG releases. Upgrade to a supported release\n'; flag++;
}
# Affected: 12.2ZH
if (check_release(version: version,
                  patched: make_list("12.2(13)ZH3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2ZJ
if (check_release(version: version,
                  patched: make_list("12.2(15)ZJ2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2ZL
if (check_release(version: version,
                  patched: make_list("12.2(15)ZL1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.3T
if (check_release(version: version,
                  patched: make_list("12.3(2)T3", "12.3(4)T1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"H323", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");


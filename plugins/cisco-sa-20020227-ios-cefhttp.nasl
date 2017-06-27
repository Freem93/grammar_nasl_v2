#TRUSTED 4089c3746531fa54064927bc64075cea770ea4554f9d07f3022db1c38554e8e8c883f90911b1fd797564403932279348d919e39a2cde4d087b54c9a5e27e4b07abbba4dc486903c9aa5aa1ee71bc295f01cfeee1a0ca435260cf136393cc778f4b85f887b62d81136e81fe5c9299032717ce92c381d72495a1269b1a89966f95225186b5cb3fe6ea6a4d0aacfbbceda21110b4ba829d941f10f091e218083e7b71381dcd03f515f9e8dcddf4a6cd27826744b1e4dd41a5cad74dd0fe397267e8c31783113f7b558771e51a464301a0ab15774fecebcb89389f87e5db0e543e605d123756e6e35562c271443e8af93758aa05b749c83f3dee2ae26f64014ab14ad8e372df246ed5461f7d7ade0162eb8ea77d4e28ea46e9e39bd84cc6e6f8c7375637bc2ae19365e1267a30461796e2a94f449f1632725a67015bfe57d4ba81de7f79875ba3529a3cfa34f3faf924505be3204868319c2e9b19fa1f9d631bae8edf0c0ea09437f87c5a7c242b42c7a721e2be4f8e46ab3e4e14abd37e0aabc744af9faefa55e33cbd4c3e747a16fdc4ae504fbae5147c79e8eae85004b4e774e551e27ec1c6376c9f89dfef7034c503f37e49a1bc5570edf976aaf93d960af4517929d0d90276c65d5897c55f6b31ce26fc73ef72e207dbea139fb373eb1ad86b8267dea244d358dc4e16c990b43766af0467c769d87ac27880fef250bb39e3a1
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080094716.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48964);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2002-0339");
 script_bugtraq_id(4191);
 script_osvdb_id(806);
 script_xref(name:"CERT", value:"310387");
 script_name(english:"Data Leak with Cisco Express Forwarding Enabled - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Excluding Cisco 12000 Series Internet Routers, all Cisco devices
running Cisco IOS software that have Cisco Express Forwarding (CEF)
enabled can leak information from previous packets that have been
handled by the device. This can happen if the packet length described
in the IP header is bigger than the physical packet size. Packets like
these will be expanded to fit the IP length and, during that expansion,
an information leak may occur. Please note that an attacker can only
collect parts of some packets but not the whole session.
No other Cisco product is vulnerable. Devices that have fast switching
enabled are not affected by this vulnerability. Cisco 12000 Series
Internet Routers are not affected by this vulnerability.
The workaround for this vulnerability is to disable CEF.
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20020227-ios-cef
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6d00f24");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080094716.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?fba0cf3a");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20020227-ios-cef.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/02/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdp58360");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu20643");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20020227-ios-cef");
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

# Affected: 11.1CC
if (check_release(version: version,
                  patched: make_list("11.1(36)CC3") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0
if (check_release(version: version,
                  patched: make_list("12.0(20.4)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(18.3)S", "12.0(19)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(18.3)ST", "12.0(19)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
if (deprecated_version(version, "12.0T")) {
 report_extra = '\n12.0T releases are vulnerable. Contact Cisco for a fix\n'; flag++;
}
# Affected: 12.0W5
if (check_release(version: version,
                  patched: make_list("12.0(20.4)W5(24.7)") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1
if (check_release(version: version,
                  patched: make_list("12.1(9.2)", "12.1(10)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8.5)E2", "12.1(8a)E","12.1(9.5)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EC
if (check_release(version: version,
                  patched: make_list("12.1(7.5)EC1", "12.1(9.5)EC") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\n12.1T releases are vulnerable. Contact Cisco for a fix\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM6") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(2.5)", "12.2(3)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(3.3)S") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(2.4)T", "12.2(4)T"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_cef_detail", "show ip cef detail");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"CEF\s+is\s+enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

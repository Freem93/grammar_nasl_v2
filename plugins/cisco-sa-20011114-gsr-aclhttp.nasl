#TRUSTED 5bdb89a04f87f8b8959d9762c1d0799a837f7a6180f976c331420d9c035afbcf0be419dda3ddd00cf664215ebade79047947e32d98827604649bc1ca9ff21cd117acd4c6b7392923ce8103c595b0dbb204e81817a8c1a9563fc48f00a985a7427b3d54af769358800bfa68306138936147e7eb7c091a6ea26b428b11644bee95870dbcdaf8cc20a07e022a6364ffa11862ed137215b63af11b31468ff98bb3cf6ec040ae28e255721a6188b293e580d19d5cbfcd2a1bbd85411ad4bea1ee442c0f7bb77c4a1ec366ba40522c2f8888f1e15004a58a5a9e333e7753b33ef9386be78684b7e8baa45e3c019811c2b0041687622517d61203942a00ac461cfb80abf64ee87fe70539f2e82d5081a17ffa8bef8f6eb85828cfe6bbb01e5c9556066f459f1275cf1e5807e1baeb5615206fe9babdef58f5e5c2285b849dc836f729d3b036ec216ee9c5df318da988d447b37502237f9216f0574577903ae1c90967c0f80649a6e9d646989d2f827ac30fd590277d0977583a2f659c7226d454a7917b5affa0d1bf95dc11430d7253da10ddd3ce4138d3a8ce134e920c964576895d990c086ba28dc985e18479d965e48cc4fe7ee27f1e9d83e506067b3e8835e9aa50eaa7f60f0055f1b31fd0327d0dadbc0bc56fa9ad8167731e0bfc4300df4df84ee4278b9eb8049129ebb48e80d69101c218757dff8e712ca1e55085cef65802a2
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b168f.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48959);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id(
  "CVE-2001-0862",
  "CVE-2001-0863",
  "CVE-2001-0864",
  "CVE-2001-0865",
  "CVE-2001-0866",
  "CVE-2001-0867"
 );
 script_bugtraq_id(3535, 3536, 3537, 3538, 3539, 3540, 3542);
 script_osvdb_id(
  1984,
  1985,
  1986,
  1987,
  1988,
  1989
 );
 script_name(english:"Multiple Vulnerabilities in Access Control List Implementation for Cisco 12000 Series Internet Router - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Six vulnerabilities involving Access Control List (ACL) has been
discovered in multiple releases of Cisco IOS Software Release for
Cisco 12000 Series Internet Routers. Not all vulnerabilities are
present in all IOS releases and only line cards based on the Engine 2
are affected by them.
No other Cisco product is vulnerable.
The workarounds are described in the Workarounds section.
');
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011114-gsr-acl
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0647406");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b168f.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?54f40b16");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20011114-gsr-acl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/11/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCddm44976");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm4476");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm44976");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt69741");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt96370");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu03323");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu35175");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu57417");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20011114-gsr-acl");
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

# Vulnerability CSCdm4476
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(10.1)S", "12.0(11)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdu57417
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(19)S", "12.0(19.3)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(18.6)ST1", "12.0(19.3)ST", "12.0(19)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdu03323
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S2", "12.0(17)S", "12.0(17.5)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(16.6)ST1", "12.0(17)ST", "12.0(17.5)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdu03323
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S2", "12.0(17)S", "12.0(17.5)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(16.6)ST1", "12.0(17)ST", "12.0(17.5)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdu35175
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(19.6)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(19.6)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdt96370
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S1", "12.0(17)S", "12.0(17.1)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(15.6)ST3", "12.0(16)ST", "12.0(17.1)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdt69741
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16.6)S2", "12.0(17)S", "12.0(17.3)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(17.3)ST", "12.0(18)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"L3\s+Engine:\s+2", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");


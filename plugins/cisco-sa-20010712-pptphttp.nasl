#TRUSTED aff0f8a3247253a0d986d5beb2e50ec2dec8a2852088697323ce71976c7dba15843a310cd412a618eb5ef8e3085bd14409a9c8ab0865679b016e67b424d2754443d86723cb44802f2762049da147b008ce11cfabe366db023278f41b69a7d6333c370e351771f2981c4f54d44afec714d313b81779982f862fa02c62394c47c2f3c9251dfa154f48e73d5225c79fa7ecb773154401e88694825f176012a5e41ea921cfd21ab2ec81bbc66a494691d8268f158007602491e05ae4817064a2eb58d92e8b0ce5cfc0fbd4c604d56245a7a9d88107880516c4cadab19e99022ddd321da6083562a404d6ee72603cc0c122193ec3fcb07f22eb8b9114f4910b35c5ff3936cdd5758f49580b5496623c9c97c89cc191025e37e3fe666c46f010e6536c039efc7d914b1da5f736b7f8a7cc264ac40b6eb66391fe8d041301efdf7d1249eea9728ea708c9c2d080f67bd3786e87ba3f8033ce56af04ff2987db616c2e71adf9ee0a5b32e385fbb744ea99527b2229329c8aca2e3590b6be2f36eed57e46707228aec6a7ddba155f55e0c90897e7c3783131244d071d7a352c5851f965332c6595a0b1e7714e7956f513589067f716fd06474b689614a550bad9894bad6f76adbd625ca298507f5ad053d744991f86aa1e8997c7172c038261018a8a400cbc92a9425c98f51a7e2ea0af882c762c7159615a7095f4a2fe9e7a987440603d
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1695.shtml

include("compat.inc");

if (description)
{
 script_id(48958);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

 script_cve_id("CVE-2001-1183");
 script_bugtraq_id(3022);
 script_osvdb_id(802);
 script_xref(name:"CERT", value:"656315");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt46181");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20010712-pptp");

 script_name(english:"Cisco IOS PPTP Vulnerability - Cisco Systems");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Point-to-Point Tunneling Protocol (PPTP) allows users to tunnel to an
Internet Protocol (IP) network using a Point-to-Point Protocol (PPP).
The protocol is described in RFC2637.

PPTP implementation using Cisco IOS software releases contains a
vulnerability that will crash a router if it receives a malformed or
crafted PPTP packet. To expose this vulnerability, PPTP must be enabled
on the router. PPTP is disabled by default. No additional special
conditions are required.

This vulnerability is present in all Cisco IOS releases that support
PPTP. PPTP is supported in the following software releases:
No other Cisco product is vulnerable.

There is no workaround for this vulnerability.");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010712-pptp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1583fe45");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00800b1695.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74cc5a95");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20010712-pptp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/07/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

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

# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(7a)E1", "12.1(8a)E", "12.1(9)E"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EZ
if (check_release(version: version,
                  patched: make_list("12.1(6)EZ2") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nUpdate to 12.2(3) or later\n'; flag++;
}
# Affected: 12.1XM
if (check_release(version: version,
                  patched: make_list("12.1(5)XM4") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1XV
if (check_release(version: version,
                  patched: make_list("12.1(5)XV3") )) {
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
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(1.1)", "12.2(3)"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(4)T") )) {
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
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"protocol\s+pptp", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

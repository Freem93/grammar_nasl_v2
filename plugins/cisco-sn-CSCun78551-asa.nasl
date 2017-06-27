#TRUSTED 670c53cd4530a47f6844ae787fa0e4879559fb6dd94a0356164a0499eddf6a47ebb152c16b135c18d4d171e486edaa1bc475616d50b55b29e98de63efc058c9054d80d61a64b44ee0d82459e981cd14e27349bf1cbc2d8a4ffe081beba6d05f3d154a3b058e845b7d23ce90be413905fec60646519f109fbac3c62e6be0ad6670954f0cd572a91c87492a11959787e7383cbcb1e06dc8ce2a7d08c3d30f06c732c786103f52c6faa3e8185646fd3bf7458299bfd40cd49368eeb47cc072e119dae1a16b92803b4491b97f24453877773c160e02d464ee12303254450bd739917f49f1a2f7015dabdd98e3b9354633fc8519989ee6784febdd3f3ad347f6685736e1127bfe6a7124fa817459e4d751ecce2adfd307b064e63e969e0fe76074c3f693f22e611b10c72c832bff982aee571539a7d370690dff7878ed2f14724c8b12bbefb8db8a9909d94daf0fcda8ac292bd4962addf41c212856ee9ccf26bdc1441615c2298a90564eefe51817d194aa4af7220c238e6fe64ec98c593e24af58182f1693093b18343158e4f535f94ad406d8f701fe94f386d6f67e8f73c640a02878cb13693edda00ea6a93c71091433c4e77ab7f7ca3b7a1345e9a5b0e8c1c65d95d7702d6089df3faafdfccdcfab8611df546e3298e69996f103797674f14f3f3a532805cae751b394732cf79c464a8a74ee2839600ff5f56afd46806c322f4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79744);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2181");
  script_bugtraq_id(67221);
  script_osvdb_id(106697);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun78551");

  script_name(english:"Cisco ASA HTTP Server Information Disclosure (CSCun78551)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by an information disclosure vulnerability in the HTTP
server. An authenticated, remote attacker can exploit this, via a
specially crafted URL, to access arbitrary files on the device.

Note that this issue affects devices in the single or multiple context
modes. However, when in multiple context mode, only a user in the
admin context can exploit this issue.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-2181
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1824a5d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34137");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCun78551.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver   = NULL;

# Convert 'Cisco versions' to dot notation
# a.b(c.d) to a.b.c.d
# a.b(c)d  to a.b.c.d
ver_dot = str_replace(string:ver, find:'(', replace:'.');
matches = eregmatch(string:ver_dot, pattern:"^(.*)\)$");

if (matches) ver_dot = matches[1];
else ver_dot = str_replace(string:ver_dot, find:')', replace:'.');

if (
  ver =~ "^8\.0([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.0.5.31", strict:FALSE) <= 0 ||
  ver =~ "^8\.2([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.2.5.48", strict:FALSE) <= 0 ||
  ver =~ "^8\.3([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.3.2.40", strict:FALSE) <= 0 ||
  ver =~ "^8\.5([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.5.1.19", strict:FALSE) <= 0 ||
  ver =~ "^8\.6([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.6.1.13", strict:FALSE) <= 0 ||
  ver =~ "^8\.7([^0-9]|$)" && ver_compare(ver:ver_dot, fix:"8.7.1.11", strict:FALSE) <= 0
)
  fixed_ver = "Refer to the vendor.";

else if (ver =~ "^8\.4([^0-9]|$)" && check_asa_release(version:ver, patched:"8.4(7.23)"))
  fixed_ver = "8.4(7.23)";

else if (ver =~ "^9\.0([^0-9]|$)" && check_asa_release(version:ver, patched:"9.0(4.12)"))
  fixed_ver = "9.0(4.12)";

else if (ver =~ "^9\.1([^0-9]|$)" && check_asa_release(version:ver, patched:"9.1(5.7)"))
  fixed_ver = "9.1(5.7)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA", ver);

override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # Check if HTTP is enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config",
    "show running-config"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"http server enable", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override)
  audit(AUDIT_HOST_NOT, "affected because the HTTP server is not enabled.");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver         +
    '\n  Fixed version     : ' + fixed_ver   +
    '\n';
  security_warning(port:0, extra:report + cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));

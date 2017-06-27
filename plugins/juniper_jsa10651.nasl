#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78422);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2014-6377");
  script_bugtraq_id(70368);
  script_osvdb_id(113077);
  script_xref(name:"IAVA", value:"2015-A-0313");
  script_xref(name:"JSA", value:"JSA10651");

  script_name(english:"Juniper JunosE Malformed ICMP Remote DoS (JSA10651)");
  script_summary(english:"Checks the JunosE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Juniper E-Series device is
potentially affected by a denial of service vulnerability. This issue
is caused by improper processing of malformed ICMP packets into the
log format for 'icmpTraffic' logging when 'DEBUG' severity is
selected.

Note that devices with logging severities below 'DEBUG' are not
affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10651");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JunosE version 13.3.3p0-1 / 14.3.2 / 15.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junose");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/JunosE/version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");
include("global_settings.inc");

# Only devices with logging severity 'DEBUG' enabled are affected
if (report_paranoia < 2) audit(AUDIT_PARANOID);

display_version = get_kb_item_or_exit('Host/JunosE/version');

item = eregmatch(string:display_version,
                 pattern:'^([0-9.]+)([pP]([0-9]+)-([0-9]+))?');
# this should not happen
if (isnull(item)) exit(1, "Failed to parse the JunosE version ("+display_version+").");
version = item[1];

fix = NULL;

# Affected: 13.x, 14.x, 15.x
# Fixes:    13.3.3p0-1, 14.3.2, 15.1.0

# 13.x check
if (version =~ "^13\.[0-3]($|[^0-9])")
{
  if (ver_compare(ver:version, fix:'13.3.3', strict:FALSE) == -1)
    fix = '13.3.3p0-1';
  else if (version == "13.3.3")
  {
    if (
      isnull(item[2]) ||
      (int(item[3]) == 0 && int(item[4]) == 0)
    ) fix = '13.3.3p0-1';
  }
}

# 14.x check
else if (version =~ "^14\.[0-3]($|[^0-9])" && ver_compare(ver:version, fix:'14.3.2', strict:FALSE) == -1)
  fix = '14.3.2';

# 15.x check
else if (version =~ "^15\.1($|[^0-9])" && ver_compare(ver:version, fix:'15.1.0', strict:FALSE) == -1)
  fix = '15.1.0';

else
  audit(AUDIT_INST_VER_NOT_VULN, 'JunosE', display_version);

if (isnull(fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'JunosE', display_version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report + junos_caveat(TRUE));
}
else security_hole(port:0, extra:junos_caveat(TRUE));

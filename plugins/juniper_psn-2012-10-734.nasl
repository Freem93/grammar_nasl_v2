#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70102);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_bugtraq_id(57331);
  script_osvdb_id(89063);

  script_name(english:"Juniper JunosE Malformed IP Option Remote DoS");
  script_summary(english:"Checks to JunosE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Juniper E-Series device is
affected by a remote denial of service vulnerability that can be
triggered by sending packets with a malformed IPv4 Option set,
resulting in a device reset. IPv6 is not vulnerable to this issue.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10539");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JunosE 10.3.3p0-10 / 11.2.3 / 11.3.3 / 12.0.3 / 12.1.2 /
12.2.1 / 12.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junose");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/JunosE/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

fix = '';

display_version = get_kb_item_or_exit('Host/JunosE/version');

item = eregmatch(string:display_version,
                 pattern:'^([0-9.]+)([pP]([0-9]+)-([0-9]+))?');
# this should not happen
if (isnull(item)) exit(1, "Failed to parse the JunosE version ("+display_version+").");
version = item[1];

# Affected: 10.x, 11.x, 12.x
# Fixes: 10.3.3p0-10, 11.2.3, 11.3.3, 12.0.3, 12.1.2, 12.2.1, 12.3.0

# 10.x checks
if (version =~ "^10(\.|$|[^0-9])")
{
  if (ver_compare(ver:version, fix:'10.3.3', strict:FALSE) == -1)
    fix = '10.3.3p0-10';
  else if (version == "10.3.3")
  {
    if (
      isnull(item[2]) ||
      (int(item[3]) == 0 && int(item[4]) < 10)
    ) fix = '10.3.3p0-10';
  }
}

# 11.x checks

if (version =~ "^11\.[012](\.|$|[^0-9])" && ver_compare(ver:version, fix:'11.2.3', strict:FALSE) == -1)
  fix = '11.2.3';

if (version =~ "^11\.3(\.|$|[^0-9])" && ver_compare(ver:version, fix:'11.3.3', strict:FALSE) == -1)
  fix = '11.3.3';


# 12.x checks
if (version =~ "^12\.0(\.|$|[^0-9])" && ver_compare(ver:version, fix:'12.0.3', strict:FALSE) == -1)
  fix = '12.0.3';

if (version =~ "^12\.1(\.|$|[^0-9])" && ver_compare(ver:version, fix:'12.1.2', strict:FALSE) == -1)
  fix = '12.1.2';

if (version =~ "^12\.2(\.|$|[^0-9])" && ver_compare(ver:version, fix:'12.2.1', strict:FALSE) == -1)
  fix = '12.2.1';

if (fix == '') audit(AUDIT_INST_VER_NOT_VULN, 'JunosE', display_version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);

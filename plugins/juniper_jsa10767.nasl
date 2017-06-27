#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94678);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2016-4925");
  script_bugtraq_id(93533);
  script_osvdb_id(145588);
  script_xref(name:"JSA", value:"JSA10767");

  script_name(english:"Juniper JUNOSe IPv6 Packet Handling Line Card Reset Remote DoS (JSA10767)");
  script_summary(english:"Checks the JunosE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the remote Juniper E-eries device is
affected by a denial of service vulnerability in the IPv6 support
component due to improper handling IPv6 packets. An unauthenticated,
remote attacker can exploit this, via a specially crafted IPv6 packet,
to cause the line card to reset.

Note that devices with IPv6 disabled are not affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10767");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper JUNOSe version 10.3.3p0-15 / 12.3.3p0-6 /
13.3.3p0-1 / 14.3.2 / 15.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junose");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/JunosE/version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");
include("global_settings.inc");

# Only E-series routers with IPv6 enabled are affected
if (report_paranoia < 2) audit(AUDIT_PARANOID);

display_version = get_kb_item_or_exit('Host/JunosE/version');

item = eregmatch(string:display_version,
                 pattern:'^([0-9.]+)([pP]([0-9]+)-([0-9]+))?');
# this should not happen
if (isnull(item)) audit(AUDIT_VER_FORMAT, display_version);
version = item[1];

fix = NULL;

# Affected: 10.x, 12.x, 13.x, 14.x, 15.x
# Fixes:    10.3.3p0-15, 12.3.3p0-6, 13.3.3p0-1, 14.3.2, 15.1.0

# 10.x check
ret = ver_compare(ver:version, fix:'10.3.3', minver:'10.0', strict:FALSE);
if(!isnull(ret))
{
  if (ret < 0) fix = '10.3.3p0-15';
  else if (ret == 0)
  {
    if ( isnull(item[2]) ||
         (int(item[3]) == 0 && int(item[4]) < 15)
    ) fix = '10.3.3p0-15';
  }
}

# 12.x check
if (isnull(fix))
{
  ret = ver_compare(ver:version, fix:'12.3.3', minver:'12.0', strict:FALSE);
  if(!isnull(ret))
  {
    if (ret < 0) fix = '12.3.3p0-6';
    else if (ret == 0)
    {
      if ( isnull(item[2]) ||
           (int(item[3]) == 0 && int(item[4]) < 6)
      ) fix = '12.3.3p0-6';
    }
  }
}

# 13.x check
if (isnull(fix))
{
  ret = ver_compare(ver:version, fix:'13.3.3', minver:'13.0', strict:FALSE);
  if(!isnull(ret))
  {
    if (ret < 0) fix = '13.3.3p0-1';
    else if (ret == 0)
    {
      if ( isnull(item[2]) ||
           (int(item[3]) == 0 && int(item[4]) < 1)
      ) fix = '13.3.3p0-1';
    }
  }
}

# 14.x check
if (isnull(fix))
{
  ret = ver_compare(ver:version, fix:'14.3.2', minver:'14.0', strict:FALSE);
  if (!isnull(ret) && ret < 0) fix = '14.3.2';
}

# 15.x check
if (isnull(fix))
{
  ret = ver_compare(ver:version, fix:'15.1.0', minver:'15.0', strict:FALSE);
  if (!isnull(ret) && ret < 0) fix = '15.1.0';
}

if (isnull(fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'JunosE', display_version);

junos_report(
  ver:display_version,
  fix:fix,
  override:TRUE,
  severity:SECURITY_HOLE
);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72726);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/22 04:30:22 $");

  script_cve_id("CVE-2014-2033");
  script_bugtraq_id(66054);
  script_osvdb_id(103879);
  script_xref(name:"CERT", value:"221620");

  script_name(english:"Blue Coat ProxySG Local User Modification Race Condition");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is potentially affected by a race condition issue.");
  script_set_attribute(attribute:"description", value:
"The remote Blue Coat ProxySG device's SGOS self-reported version is
prior to 6.5.4.0.  It is, therefore, potentially affected by a race
condition issue during the time before the new changes take effect after
a local user account modification due to configuration caching.  User
account modifications include password changes, user account deletion,
or the addition or removal of a user account to a user list. 

Note that this issue only affects user accounts using local realm
authentication.");
  script_set_attribute(attribute:"see_also", value:"https://kb.bluecoat.com/index?page=content&id=SA77");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.5.4.0 or refer to the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/27");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;


if (version =~ "^6\.5\." && ver_compare(ver:version, fix:"6.5.4.0", strict:FALSE) == -1)
{
  fix    = '6.5.4.0';
  ui_fix = '6.5.4.0 Build 0';

  # Select fixed version for report
  if (isnull(ui_version)) report_fix = fix;
  else report_fix = ui_fix;
}
else if (
  version =~ "^6\.4\.([0-5]\.[0-9]+|6\.[01])($|[^0-9])" ||
  version =~ "^6\.2\.((([0-9]|1[0-4])\.[0-9]+)|15\.[0-3])($|[^0-9])" ||
  version =~ "^6\.1\.(([0-5]\.[0-9]+)|6\.[0-3])($|[^0-9])" ||
  version =~ "^5\.5\.((([0-9]|10)\.[0-9]+)|(11\.[0-3]))($|[^0-9])"
) report_fix = "A fix is not yet available.";
else if (
  version =~ "^6\.3\." ||
  version =~ "^5\.[0-4]\." ||
  version =~ "^[0-4]\."
) report_fix = "Upgrade to a later version.";

if (report_fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + report_ver +
      '\n  Fixed version     : ' + report_fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Blue Coat ProxySG', version);

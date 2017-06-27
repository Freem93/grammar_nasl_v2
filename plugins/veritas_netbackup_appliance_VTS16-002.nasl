#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94671);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2016-7399");
  script_osvdb_id(145131);

  script_name(english:"Veritas NetBackup Appliance 2.6.0.x / 2.6.1.x / 2.7.x RCE (VTS16-002)");
  script_summary(english:"Checks the version of NetBackup Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup management appliance is affected by a remote
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Veritas NetBackup
Appliance is 2.6.0.x equal or prior to 2.6.0.4, 2.6.1.x equal or prior
to 2.6.1.2, or 2.7.x equal or prior to 2.7.3. It is, therefore,
affected by an unspecified flaw that allows an unauthenticated, remote
attacker to execute arbitrary commands with root privileges.

Note that Nessus did not check to see if an available hotfix was
applied.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS16-002.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas NetBackup Appliance version 2.6.0.4, 2.6.1.2, or
2.7.3, and then apply the relevant hotfix as referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("veritas_netbackup_appliance_web_console_detect.nbin");
  script_require_keys("installed_sw/NetBackup Appliance");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "NetBackup Appliance";

install = get_single_install(
  app_name : app,
  combined : TRUE,
  exit_if_unknown_ver : TRUE
);

port            = install["port"];
path            = install["path"];
version         = install["version"];
display_version = install["display_version"];

# Require 3 version parts for 2.7.x and 4 parts for 2.6.0.x
if (version =~ '^2(\\.[67]|\\.6\\.0)?$')
  audit(AUDIT_VER_NOT_GRANULAR, app, port, display_version);

if (version =~ '^2\\.6\\.1$' && report_paranoia < 2)
  audit(AUDIT_VER_NOT_GRANULAR, app, port, display_version);

vers = make_array();

vers['2.7']['fix']    = '2.7.3';
vers['2.7']['minver'] = '2.7.0';
vers['2.7']['hotfix'] = 'ET3900678';

vers['2.6.1']['fix']    = '2.6.1.2';
vers['2.6.1']['minver'] = '2.6.1.0';
vers['2.6.1']['hotfix'] = 'ET3900680';

vers['2.6.0']['fix']    = '2.6.0.4';
vers['2.6.0']['minver'] = '2.6.0.1';
vers['2.6.0']['hotfix'] = 'ET3900681';

caveat    = '';
fixed_ver = '';

foreach ver(vers)
{
  ret = ver_compare(ver:version, fix:ver['fix'], minver:ver['minver']);
  if(!isnull(ret) && ret <= 0)
  {
    # If the version matches the fixed version, we don't know whether or not the hotfix
    # has been applied, so exit unless report paranoia is Paranoid
    if(ret == 0)
    {
      if(report_paranoia < 2)
        audit(AUDIT_PARANOID);
      caveat =
        '\n  Note that Nessus did not check to see if the hotfix has' +
        '\n  been applied.\n';
    }

    # If the version is below the fixed version, we know the hotfix hasn't been applied
    # because it requires upgrade to the latest version as a prerequisite
    fixed_ver = ver['fix'] + ' hotfix ' + ver['hotfix'];
    break;
  }
}

if(empty_or_null(fixed_ver))
  audit(AUDIT_INST_PATH_NOT_VULN, app, display_version, path);

install_url = build_url(port:port, qs:path);

items  = make_array(
  "Path", install_url,
  "Installed version", display_version,
  "Fixed version", fixed_ver
);
order  = make_list("Path","Installed version","Fixed version");
report = report_items_str(report_items:items, ordered_fields:order) + caveat;

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);

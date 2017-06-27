#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72982);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/23 22:05:01 $");

  script_name(english:"Oracle RDBMS Patchset Out of Date (credentialed check)");
  script_summary(english:"Checks the Oracle Database patchset level.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is not up to date.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Database server installed on the remote host is
an unsupported patchset level.");
  script_set_attribute(attribute:"solution", value:"Install the latest patchset.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_patch_info.nbin");
  script_require_keys("Oracle/Patches/local");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");

get_kb_item_or_exit("Oracle/Patches/local");
installs = find_oracle_databases();
if (isnull(installs)) exit(0, 'No Oracle Databases were found on the remote host.');

res = get_oracledb_host_os_and_port();
os = res['os'];
port = res['port'];

vuln = 0;
foreach ohome(installs)
{
  version = ohome['version'];
  if (isnull(version)) continue;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] == 11 &&
    (ver[1] == 2 && ver[2] == 0 && ver[3] < 4)
  )
  {
    vuln++;
    if (max_index(split(ohome['sids'], sep:',', keep:FALSE)) > 1) s = 's ';
    else s = ' ';

    report +=
      '\n  SID'+s+'             : ' + ohome['sids'] +
      '\n  Oracle home path : ' + ohome['path'] +
      '\n  Database version : ' + version + '\n';
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's of Oracle Database are';
    else s = ' of Oracle Database is';

    report =
      '\n' +
      'The following vulnerable instance'+s+' installed on the\n' +
      'remote host :\n' +
      report + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');

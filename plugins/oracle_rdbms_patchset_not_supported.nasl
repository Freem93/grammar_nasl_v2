#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72981);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 13:24:35 $");

  script_name(english:"Oracle RDBMS Patchset Out of Date (remote check)");
  script_summary(english:"Checks the Oracle Database patchset level.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is not up to date.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Database server installed on the remote host is
an unsupported patchset level.");
  script_set_attribute(attribute:"solution", value:
"Install the latest patchset.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_detect.nbin");
  script_require_ports("Services/oracle_tnslsnr", 1521);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");

port = get_service(svc:"oracle_tnslsnr", default:1521, exit_on_fail:TRUE);

tnslsnr = get_kb_item_or_exit('oracle_tnslsnr/'+port+'/version');

service_type = get_kb_item_or_exit("Oracle/service_type");
service = get_kb_item_or_exit("Oracle/"+service_type);

os = get_oracle_os(tnslsnr:tnslsnr);
if (os == 'unknown') exit(1, UNKNOWN_TNSLSNR = tnslsnr);

version = get_oracle_version(tnslsnr:tnslsnr);
if (isnull(version)) exit(1, "Can't determine the Oracle TNSLSNR version for " +service_type+ " " +service+ " on port "+port+".");

# Only run this check for supported versions of Oracle database
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

vuln = 0;
if (
  ver[0] == 11 &&
  (ver[1] == 2 && ver[2] == 0 && ver[3] < 4)
)
{
  ohomes = get_kb_list('Oracle/'+service+'/*/Path');
  if (isnull(ohomes))
  {
    vuln++;
    report += '\n  ' +service_type+ ' : ' + service + '\n';
  }
  else
  {
    foreach ohome (keys(ohomes))
    {
      vuln++;
      path = ohomes[ohome];
      ohome = ohome - '/Path';

      report +=
        '\n  ' +service_type+ ' : ' + service +
        '\n  Oracle home path : ' + path +
        '\n  Database version : ' + version + '\n';
    }
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');

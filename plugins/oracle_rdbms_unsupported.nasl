#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55786);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/08/22 23:35:29 $");

  script_name(english:"Oracle Database Unsupported Version Detection");
  script_summary(english:"Checks the version of Oracle Database.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a database
server.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Oracle Database running
on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www.oracle.com/us/support/library/lifetime-support-technology-069183.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccd068d1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Oracle Database that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_detect.nbin", "oracle_rdbms_patch_info.nbin");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");

fixed = '11.2.0.0';
supported_versions = '11.2.0 / 12.1.0';

if (get_kb_list('oracle_tnslsnr/*/version'))
{
  # First try to perform detection remotely
  port = get_kb_item_or_exit('Services/oracle_tnslsnr');

  tnsstr = get_kb_item_or_exit('oracle_tnslsnr/'+port+'/version');
  version = ereg_replace(string:tnsstr, pattern:"^TNS(LSNR)? for .*: Version ([0-9\.]+).*", replace:"\2");
  if (version !~ '^[0-9]+\\.[0-9\\.]+$') exit(1, 'Failed to extract the version number from the TNS Listener string '+tnsstr+'.');

  fixed = '11.2.0.0';
  if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
  {
    register_unsupported_product(product_name:"Oracle Database Server",
                                 cpe_base:"oracle:database_server", version:version);

    report =
      '\n  Version source     : ' + tnsstr +
      '\n  Installed version  : ' + version +
      '\n  Supported versions : ' + supported_versions + '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  }
  else exit(0, 'The Oracle Database server '+version+' install listening on port '+port+' is currently supported.');
}
else if (get_kb_item("Oracle/Patches/local"))
{
  # Fall back to local detection
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
    if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
    {
      vuln++;
      register_unsupported_product(product_name:"Oracle Database Server",
                                   cpe_base:"oracle:database_server", version:version);
      if (max_index(split(ohome['sids'], sep:',', keep:FALSE)) > 1) s = 's ';
      else s = ' ';

      report +=
        '\n  SID'+s+'               : ' + ohome['sids'] +
        '\n  Oracle home path   : ' + ohome['path'] +
        '\n  Database version   : ' + version + 
        '\n  Supported versions : ' + supported_versions +
        '\n  EOL URL            : http://www.oracle.com/us/support/library/lifetime-support-technology-069183.pdf' + '\n';
    }
  }

  if (vuln)
  {
    if (vuln > 1) s = 's of Oracle Database are';
    else s = ' of Oracle Database is';

    report =
      '\n' +
      'The following unsupported instance'+s+' installed on the\n' +
      'remote host :\n' +
      report + '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  }
  audit(AUDIT_HOST_NOT, 'affected');
}
exit(0, 'No Oracle Databases were found on the remote host.');
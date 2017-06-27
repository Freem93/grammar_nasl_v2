#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91335);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/27 14:13:21 $");

  script_cve_id(
    "CVE-2016-0211",
    "CVE-2016-0215"
  );
  script_osvdb_id(
    136875,
    136876
  );

  script_name(english:"IBM DB2 9.7 < FP11 Special Build 35317 / 10.1 < FP5 Special Build 35316 / 10.5 < FP7 Special Build 35315 Multiple Vulnerabilities (UNIX)");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is either 9.7 prior to fix pack 11 Special Build 35317,
10.1 prior to fix pack 5 Special Build 35316, or 10.5 prior to fix
pack 7 Special Build 35315. It is, therefore, affected by the
following vulnerabilities :

  - A denial of service vulnerability exists in LUW related
    to the handling of DRDA messages. An authenticated,
    remote attacker can exploit this, via a specially
    crafted DRDA message, to cause the DB2 server to
    terminate abnormally. (CVE-2016-0211)

  - A denial of service vulnerability exists in LUW when
    handling SELECT statements with subqueries containing
    the AVG OLAP function that are applied to Oracle
    compatible databases. An authenticated, remote attacker
    can exploit this, via a specially crafted query, to
    cause the DB2 server to terminate abnormally.
    (CVE-2016-0215)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979984");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979986");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Special Build based on the most recent
fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("db2_installed.nbin");
  script_require_keys("installed_sw/DB2 Server");
  script_exclude_keys("SMB/db2/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# The remote host's OS is Windows, not Linux.
if (get_kb_item("SMB/db2/Installed")) audit(AUDIT_OS_NOT, "Linux", "Windows");

app_name = "DB2 Server";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];
special_build = install['special_build'];
port     = 0;

# DB2 has an optional OpenSSH server that will run on 
# windows.  We need to exit out if we picked up the windows
# installation that way.
if ("Windows" >< install['platform'])
  audit(AUDIT_HOST_NOT, "Linux based operating system");

fix_ver = NULL;
fix_build = NULL;
if (version =~ "^9\.7\.")
{
  fix_ver = "9.7.0.11";
  fix_build = "35317";
}
else if (version =~ "^10\.1\.")
{
  fix_ver = "10.1.0.5";
  fix_build = "35316";
}
else if (version =~ "^10\.5\.")
{
  fix_ver = "10.5.0.7";
  fix_build = "35315";
}

vuln = FALSE;
if (!isnull(fix_ver))
{
  cmp = ver_compare(ver:version, fix:fix_ver, strict:FALSE);
  # less than current fix pack
  if(cmp < 0)
    vuln = TRUE;
  else if (cmp == 0)
  {
    # missing special build or less than current special build
    if (special_build == "None" || ver_compare(ver:special_build, fix:fix_build, strict:FALSE) < 0)
      vuln = TRUE;
  }
}

if (vuln)
{
  report =
    '\n  Product                 : ' + app_name +
    '\n  Path                    : ' + path +
    '\n  Installed version       : ' + version +
    '\n  Installed Special Build : ' + special_build +
    '\n  Fixed version           : ' + fix_ver +
    '\n  Special Build           : ' + fix_build + '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else
{
  ver_str = version;
  if (special_build != "None")
    ver_str += " with Special Build " + special_build;
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver_str, path);
}

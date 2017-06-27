#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91337);
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

  script_name(english:"IBM DB2 Connect 9.7 < FP11 Special Build 35317 / 10.1 < FP5 Special Build 35316 / 10.5 < FP7 Special Build 35315 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks the DB2 Connect signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 Connect running
on the remote Windows host is either 9.7 prior to fix pack 11 Special
Build 35317, 10.1 prior to fix pack 5 Special Build 35316, or 10.5
prior to fix pack 7 Special Build 35315. It is, therefore, affected by
the following vulnerabilities :

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
    (CVE-2016-0215)

Note that the IBM DB2 Connect installation is affected only if a local
database has been created.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979984");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979986");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Connect Special Build based on the most
recent fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2_connect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2_connect/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "DB2 Connect Server";
if(!get_kb_item("SMB/db2_connect/Installed")) audit(AUDIT_NOT_INST, app);
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

kb_version = install['version'];
ver_parts = split(kb_version, sep:".", keep:FALSE);
if (len(ver_parts) < 3)
  audit(AUDIT_VER_NOT_GRANULAR, app, kb_version);

# concatenate version parts
version = ver_parts[0]+"."+ver_parts[1]+"."+ver_parts[2];

fix_ver = NULL;
fix_build = NULL;
if (version =~ "^9\.7\.")
{
  fix_ver = "9.7.1100";
  fix_build = "35317";
}
else if (version =~ "^10\.1\.")
{
  fix_ver = "10.1.500";
  fix_build = "35316";
}
else if (version =~ "^10\.5\.")
{
  fix_ver = "10.5.700";
  fix_build = "35315";
}

path = install['path'];
special_build = install['special_build'];
info = "";

if (!isnull(fix_ver))
{
  vuln = FALSE;
  cmp = ver_compare(ver:version, fix:fix_ver, strict:FALSE);
  # less than current fix pack                                      
  if(cmp <  0)
    vuln = TRUE;
  else if (cmp == 0)
  {
    # missing special build or less than current special build      
    if (special_build == "None" || ver_compare(ver:special_build, fix:fix_build, strict:FALSE) < 0)
      vuln = TRUE;
  }
  if (vuln)
  {
    info +=
      '\n  Product                 : ' + app +
      '\n  Path                    : ' + path +
      '\n  Installed version       : ' + version +
      '\n  Installed Special Build : ' + special_build +
      '\n  Fixed version           : ' + fix_ver +
      '\n  Fixed Special Build     : ' + fix_build + '\n' +
      '\n';
  }
}

# Report if vulnerable install was found.
if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  security_report_v4(port:port, extra:info, severity:SECURITY_WARNING);
}
else
{
  ver_str = kb_version;
  if (special_build != "None") ver_str += " with Special Build " + special_build;
  audit(AUDIT_INST_VER_NOT_VULN, app, ver_str);
}

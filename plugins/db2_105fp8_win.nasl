#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94899);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_osvdb_id(144371, 144373);

  script_name(english:"IBM DB2 10.5 < Fix Pack 8 Multiple DoS");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 10.5 running on
the remote host is prior to Fix Pack 8. It is, therefore, affected by
the following vulnerabilities :

  - A denial of service vulnerability exists in the
    SQLNP_SCOPE_TRIAL() function due to improper handling of
    SQL statements. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 144371)

  - A denial of service vulnerability exists in the Query
    Compiler QGM due to improper handling of specific
    queries. An authenticated, remote attacker can exploit
    this, via a specially crafted query, to crash the
    database. (VulnDB 144373)");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21633303#8");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 10.5 Fix Pack 8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_ports("SMB/db2/Installed", "SMB/db2_connect/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check each installation.
db2_installed = get_kb_item("SMB/db2/Installed");
if (db2_installed)
  db2_installs = get_kb_list("SMB/db2/*");

db2connect_installed = get_kb_item("SMB/db2_connect/Installed");
if (db2_installed)
  db2connect_installs = get_kb_list("SMB/db2_connect/*");

if (!db2_installed && !db2connect_installed)
  audit(AUDIT_NOT_INST, "DB2 and/or DB2 Connect");

info = "";
fix_version = '10.5.800.381';
not_affected = make_list();

# Check DB2 first
foreach install(sort(keys(db2_installs)))
{
  if ("/Installed" >< install) continue;

  version = db2_installs[install];

  prod = install - "SMB/db2/";
  prod = prod - (strstr(prod, "/"));

  path = install - "SMB/db2/";
  path = path - (prod + "/");

  if (version =~ "^10\.5\." && ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_version +
      '\n';
  }
  else
    not_affected = make_list(not_affected, prod + ' version ' + version + ' at ' + path);
}

# Check DB2 Connect second
foreach install(sort(keys(db2connect_installs)))
{
  if ("/Installed" >< install) continue;

  version = db2connect_installs[install];

  prod = install - "SMB/db2_connect/";
  prod = prod - (strstr(prod, "/"));

  path = install - "SMB/db2_connect/";
  path = path - (prod + "/");

  if (version =~ "^10\.5\." && ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_version +
      '\n';
  }
  else
    not_affected = make_list(not_affected, prod + ' version ' + version + ' at ' + path);
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

# Report if vulnerable installs were found.
if (info)
{

  security_report_v4(port:port, extra:info, severity:SECURITY_WARNING);
  exit(0);
}
else
{
  if (max_index(not_affected) > 1)
    exit(0, join(not_affected, sep:", ") + " are installed and, therefore, not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, not_affected[0]);
}

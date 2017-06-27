#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70456);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 21:08:26 $");

  script_cve_id("CVE-2013-4032", "CVE-2013-4033");
  script_bugtraq_id(62018, 62747);
  script_osvdb_id(96654, 97950);

  script_name(english:"IBM DB2 10.1 < Fix Pack 3 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks DB2 signature");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote database server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the installation of IBM DB2 10.1 on the
remote host is affected by the following vulnerabilities :

  - When a multi-node configuration is used, an error exists
    in the Fast Communications Manager (FCM) that could
    allow denial of service attacks. (CVE-2013-4032 /
    IC94434)

  - An unspecified error exists that can allow an attacker
    to gain SELECT, INSERT, UPDATE, or DELETE permissions to
    database tables. Note that successful exploitation
    requires the rights EXPLAIN, SQLADM, or DBADM.
    (CVE-2013-4033 / IC94757)"
  );
  # https://www.ibm.com/blogs/psirt/security-bulletin-ibm-smart-analytics-system-5600-v3-is-affected-by-a-vulnerability-in-the-ibm-db2-fast-communications-manager-cve-2013-4032/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c3d99f6");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21610582");
  # Advisory IC94434
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21650231");
  # Advisory IC94757
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21646809");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 Version 10.1 Fix Pack 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2_connect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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
fix_version = '10.1.300.533';
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

  if (version =~ "^10\.1\." && ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
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

  if (version =~ "^10\.1\." && ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
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

  if (report_verbosity > 0)
    security_warning(port:port, extra:info);
  else security_warning(port);
  exit(0);
}
else
{
  if (max_index(not_affected) > 1)
    exit(0, join(not_affected, sep:", ") + " are installed and thus, not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, not_affected[0]);
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64502);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/12/08 21:32:49 $");

  script_cve_id("CVE-2012-4414");
  script_bugtraq_id(55498);
  script_osvdb_id(89050);

  script_name(english:"MariaDB Binary Log SQL Injection");
  script_summary(english:"Checks version of MariaDB");

  script_set_attribute(attribute:"synopsis", value:
"The database server running on the remote host is affected by multiple
SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of MariaDB
running on the remote host has multiple SQL injection vulnerabilities.
User-supplied identifiers are not properly quoted before being written
into the binary log. An attacker with a valid account and privileges
to modify data could exploit this to modify tables that they should
not have access to.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-382");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2012/09/11/4");
  script_set_attribute(attribute:"solution", value:"Upgrade to MariaDB 5.5.27 / 5.3.8 / 5.2.13 / 5.1.66 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");  
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/10"); 
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("audit.inc");
include("mysql_version.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);
mysql_init(port:port, exit_on_fail:TRUE);

if (!is_mariadb()) audit(AUDIT_NOT_LISTEN, 'MariaDB', port);

ver = mysql_get_version();
if (isnull(ver)) exit(1, 'Failed to get the version from the MariaDB server listening on port '+port+'.');

# Fix up MariaDB version.
real_ver = ver;
match = eregmatch(pattern:"^5\.5\.5-([0-9]+\.[0-9]+\.[0-9]+)-MariaDB", string:ver);
if (!isnull(match)) ver = match[1];

if (mysql_ver_cmp(ver:ver, fix:'5.5.27', same_branch:TRUE) < 0)
   fix = '5.5.27-MariaDB';
else if (mysql_ver_cmp(ver:ver, fix:'5.3.8', same_branch:TRUE)  < 0)
  fix = '5.3.8-MariaDB';
else if (mysql_ver_cmp(ver:ver, fix:'5.2.13', same_branch:TRUE) < 0)
   fix = '5.2.13-MariaDB';
else if (mysql_ver_cmp(ver:ver, fix:'5.1.66', same_branch:TRUE)  < 0)
   fix = '5.1.66-MariaDB';
else
  fix = NULL;

if (isnull(fix))
  audit(AUDIT_LISTEN_NOT_VULN, 'MariaDB', port, ver);
else
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);


if (report_verbosity > 0)
{
  ver_ui = ver;
  if (ver != real_ver) ver_ui += " (" + real_ver + ")";

  report =
    '\n  Installed version : ' + ver_ui +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

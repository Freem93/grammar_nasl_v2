#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64503);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/24 02:15:10 $");

  script_cve_id("CVE-2012-4414");
  script_bugtraq_id(55498);
  script_osvdb_id(89050);

  script_name(english:"MySQL Binary Log SQL Injection");
  script_summary(english:"Checks version of MySQL");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The database server running on the remote host has multiple SQL
injection vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MySQL installed on the remote host is earlier than
5.5.33 / 5.6.x earlier than 5.6.13 and is, therefore, potentially
affected by multiple SQL injection vulnerabilities.  User-supplied
identifiers are not properly quoted before being written into the
binary log.  An attacker with a valid account and privileges to modify
data could exploit this to modify tables that they should not have
access to."
  );
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-33.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-13.html");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-382");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2012/09/11/4");
  # http://www.mysqlperformanceblog.com/2013/01/13/cve-2012-4414-in-mysql-5-5-29-and-percona-server-5-5-29/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8d7daf3");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.5.33 / 5.6.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");  # mailing list announcement
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
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

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);
mysql_init(port:port, exit_on_fail:TRUE);

if (is_mariadb()) audit(AUDIT_NOT_LISTEN, 'MySQL', port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = mysql_get_version();

if (mysql_ver_cmp(ver:ver, fix:'5.6.13', same_branch:TRUE) < 0)
  fix = '5.6.13';
else if (mysql_ver_cmp(ver:ver, fix:'5.5.33', same_branch:FALSE)  < 0)
  fix = '5.5.33 / 5.6.13';
else
  audit(AUDIT_LISTEN_NOT_VULN, 'MySQL', port, ver);


set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

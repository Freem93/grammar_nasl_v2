#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46328);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/26 01:15:51 $");

  script_cve_id("CVE-2010-1621", "CVE-2010-1626");
  script_bugtraq_id(39543, 40257);
  script_osvdb_id(63903, 64843);

  script_name(english:"MySQL Community Server 5.1 < 5.1.46 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL 5.1 Server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Community Server 5.1 installed on the remote host
is earlier than 5.1.46 and thus potentially affected by the following
vulnerabilities :

  - A local user may be able to issue a 'DROP TABLE' command
    for one MyISAM table and remove the data and index files
    of a different MyISAM table. (Bug #40980)

  - The application does not correct check privileges in
    calls to 'UNINSTALL PLUGIN', which could be abused by
    an unprivileged user to uninstall plugins loaded
    dynamically. (Bug #51770)");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=40980");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=51770");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-46.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Community Server 5.1.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);
vuln = FALSE;

if (mysql_init(port:port, exit_on_fail:TRUE) == 1)
{
  variant = mysql_get_variant();
  version = mysql_get_version();

  ver_fields = split(version, sep:'.', keep:FALSE);
  major = int(ver_fields[0]);
  minor = int(ver_fields[1]);
  rev = int(ver_fields[2]);

  if (
    !isnull(variant) && "Community" >< variant &&
    strlen(version) &&
    major == 5 && minor == 1 && rev < 46
  ) vuln = TRUE;
}
else exit(1, "Can't establish a MySQL connection on port "+port+".");
mysql_close();


if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\nInstalled version : ' + version +
             '\nFixed version     : 5.1.46\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else
{
  if (isnull(variant)) exit(1, "Can't determine the variant of MySQL listening on port "+port+".");
  else if ("Community" >< variant) exit(0, "MySQL version "+version+" is listening on port "+port+" and is not affected.");
  else exit(0, "MySQL "+variant+" is listening on port "+port+" and is not affected.");
}

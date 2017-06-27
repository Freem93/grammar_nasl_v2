#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47158);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/05/26 01:15:51 $");

  script_cve_id("CVE-2010-2008");
  script_bugtraq_id(41198);
  script_osvdb_id(65851);
  script_xref(name:"Secunia", value:"40333");

  script_name(english:"MySQL Community Server < 5.1.48 Denial of Service");
  script_summary(english:"Checks version of MySQL 5.1 Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Community Server installed on the remote host is
earlier than 5.1.48 and thus potentially affected by a denial of
service vulnerability.

The 'ALTER DATABASE' command can be misused by a user with 'ALTER'
permissions to cause the MySQL data directory to become unusable.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=53804");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-48.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Community Server 5.1.48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/29");

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
    major == 5 && minor == 1 && rev < 48
  ) vuln = TRUE;
}
else exit(1, "Can't establish a MySQL connection on port "+port+".");
mysql_close();

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 5.1.48\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else
{
  if (isnull(variant)) exit(1, "Can't determine the variant of MySQL listening on port "+port+".");
  else if ("Community" >< variant) exit(0, "MySQL version "+version+" is listening on port "+port+" and is not affected.");
  else exit(0, "MySQL "+variant+" is listening on port "+port+" and is not affected.");
}

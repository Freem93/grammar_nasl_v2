#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46702);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850");
  script_bugtraq_id(40100, 40106, 40109);
  script_osvdb_id(64586, 64587, 64588);

  script_name(english:"MySQL Community Server < 5.1.47 / 5.0.91 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL 5.1 Server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Community Server installed on the remote host is
earlier than 5.1.47 / 5.0.91 and is, therefore, potentially affected
by the following vulnerabilities :

  - The server may continue reading packets indefinitely
    if it receives a packet larger than the maximum size
    of one packet, which could allow an unauthenticated,
    remote attacker to consume a high level of CPU
    and bandwidth. (Bug #50974)

  - Using an overly long table name argument to the
    'COM_FIELD_LIST' command, an authenticated user can
    overflow a buffer and execute arbitrary code on the
    affected host. (Bug #53237)

  - Using a specially crafted table name argument to
    'COM_FIELD_LIST', an authenticated user can bypass
    almost all forms of checks for privileges and table-
    level grants. (Bug #53371)");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=50974");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=53237");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=53371");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-91.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Community Server 5.1.47 / 5.0.91 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
    (
      major == 5 && minor == 1 && rev < 47 ||
      major == 5 && minor == 0 && rev < 91
    )
  ) vuln = TRUE;
}
else exit(1, "Can't establish a MySQL connection on port "+port+".");
mysql_close();


if (vuln)
{
  if (report_verbosity > 0)
  {
    if (minor == 0) fixed_version = "5.0.91";
    else fixed_version = "5.1.47";

    report = '\nInstalled version : ' + version +
             '\nFixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
{
  if (isnull(variant)) exit(1, "Can't determine the variant of MySQL listening on port "+port+".");
  else if ("Community" >< variant) exit(0, "MySQL version "+version+" is listening on port "+port+" and is not affected.");
  else exit(0, "MySQL "+variant+" is listening on port "+port+" and is not affected.");
}

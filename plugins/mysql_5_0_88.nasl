#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42899);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id("CVE-2012-4452", "CVE-2009-4019", "CVE-2009-4028", "CVE-2008-7247");
  script_bugtraq_id(37076, 37297, 38043);
  script_osvdb_id(60487, 60488, 60489, 60664, 60665);
  script_xref(name:"Secunia", value:"37372");

  script_name(english:"MySQL 5.0 < 5.0.88 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL 5.0 Server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.0 installed on the remote host is earlier than
5.0.88. It is, therefore, potentially affected by the following
vulnerabilities :

  - MySQL clients linked against OpenSSL are vulnerable
    to man-in-the-middle attacks. (Bug #47320)

  - The GeomFromWKB() function can be manipulated
    to cause a denial of service. (Bug #47780)

  - Specially crafted SELECT statements containing sub-
    queries in the WHERE clause can cause the server
    to crash. (Bug #48291)

  - It is possible to bypass access restrictions when the
    data directory contains a symbolic link to a different
    file system. (Bug #39277)");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=47320");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=47780");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=48291");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=39277");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-88.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 5.0.88 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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
    major == 5 && minor == 0 && rev < 88
  )
  {
    vuln = TRUE;
  }
}
else exit(1, "Can't establish a MySQL connection on port "+port+".");

mysql_close();

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '
Installed version : ' + version + '
Fixed version     : 5.0.88
';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  if (isnull(variant)) exit(1, "Can't determine the variant of MySQL listening on port "+port+".");
  else if ("Community" >< variant) exit(0, "MySQL version "+version+" is listening on port "+port+" and is not affected.");
  else exit(0, "MySQL "+variant+" is listening on port "+port+" and is not affected.");
}

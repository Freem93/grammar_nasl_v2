#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49711);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id(
    "CVE-2009-5026",
    "CVE-2010-3833",
    "CVE-2010-3834",
    "CVE-2010-3835",
    "CVE-2010-3836",
    "CVE-2010-3837",
    "CVE-2010-3838",
    "CVE-2010-3839",
    "CVE-2010-3840"
  );
  script_bugtraq_id(43676, 43677);
  script_osvdb_id(69001, 69387, 69389, 69390, 69391, 69392, 69393, 69394, 69395, 69396);
  script_xref(name:"Secunia", value:"41716");

  script_name(english:"MySQL Community Server < 5.1.51 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL 5.1 Server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Community Server installed on the remote host is
earlier than 5.1.51 and is, therefore, potentially affected by
multiple vulnerabilities:

  - A privilege escalation vulnerability exists when using
    statement-based replication. Version specific comments
    used on a master server with a lesser release version
    than its slave can allow the MySQL privilege system on
    the slave server to be subverted. (49124)

  - An authenticated user can crash the MySQL server by
    passing improper WKB to the 'PolyFromWKB()' function.
    (51875)

  - The improper handling of type errors during argument
    evaluation in extreme-value functions, e.g., 'LEAST()'
    or 'GREATEST()' caused server crashes. (55826)

  - The creation of derived tables needing a temporary
    grouping table caused server crashes. (55568)

  - The re-evaluation of a user-variable assignment
    expression after the creation of a temporary table
    caused server crashes. (55564)

  - The 'convert_tz()' function can be used to crash the
    server by setting the timezone argument to an empty
    SET column value. (55424)

  - The pre-evaluation of 'LIKE' predicates while preparing
    a view caused server crashes. (54568)

  - The use of 'GROUP_CONCAT()' and 'WITH ROLLUP' caused
    server crashes. (54476)

  - The use of an intermediate temporary table and queries
    containing calls to 'GREATEST()' or 'LEAST()', having
    a list of both numeric and 'LONGBLOB' arguments, caused
    server crashes. (54461)

  - The use of nested joins in prepared statements or
    stored procedures could result in infinite loops.
    (53544)");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=49124");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=51875");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=55826");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=55568");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=55564");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=54568");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=54476");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=54461");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=53544");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-50.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-51.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Community Server 5.1.51 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/05");

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
    major == 5 && minor == 1 && rev < 51
  ) vuln = TRUE;

}
else exit(1, "Can't establish a MySQL connection on port "+port+".");
mysql_close();

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 5.1.51\n';
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

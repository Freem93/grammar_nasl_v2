#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48759);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id(
    "CVE-2010-3676",
    "CVE-2010-3677",
    "CVE-2010-3678",
    "CVE-2010-3679",
    "CVE-2010-3680",
    "CVE-2010-3681",
    "CVE-2010-3682",
    "CVE-2010-3683"
  );
  script_bugtraq_id(42596, 42598, 42599, 42625, 42633, 42638, 42643, 42646);
  script_osvdb_id(
    67377,
    67378,
    67379,
    67380,
    67381,
    67382,
    67383,
    67384,
    69000
  );
  script_xref(name:"Secunia", value:"41048");

  script_name(english:"MySQL Community Server < 5.1.49 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL 5.1 Server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Community Server installed on the remote host is
earlier than 5.1.49 and thus potentially affected by multiple
vulnerabilities:

  - DDL statements could cause the server to crash. (55039)

  - Joins involving a table with a unique SET column could
    cause the server to crash. (54575)

  - Incorrect handling of NULL arguments for IN or CASE
    operations involving the WITH ROLLUP modifier could
    cause the server to crash. (54477)

  - A malformed argument to the BINLOG statement could
    cause the server to crash. (54393)

  - Using TEMPORARY InnoDB tables with nullable columns
    could cause the server to crash. (54044)

  - Alternate reads with two indexes on a table using the
    HANDLER interface could cause the server to crash.
    (54007)

  - Using EXPLAIN with queries of the form SELECT ... UNION
    ... ORDER BY (SELECT ... WHERE ...) could cause the
    server to crash. (52711)

  - LOAD DATA INFILE did not check for SQL errors sent and
    even if errors were already reported, it sent an OK
    packet. Also, an assert was sometimes raised when it
    should not have been relating to client-server protocol
    checking in debug servers. (52512)");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=55039");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=55475");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=54477");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=54393");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=54044");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=54007");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=52711");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=52512");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-49.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Community Server 5.1.49 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/26");

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
    major == 5 && minor == 1 && rev < 49
  ) vuln = TRUE;

}
else exit(1, "Can't establish a MySQL connection on port "+port+".");
mysql_close();

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 5.1.49\n';
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

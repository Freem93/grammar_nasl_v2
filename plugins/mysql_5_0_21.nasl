#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17697);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2006-1516", "CVE-2006-1517", "CVE-2006-1518");
  script_bugtraq_id(17780);
  script_osvdb_id(25226, 25227, 25228);
  script_xref(name:"CERT", value:"602457");

  script_name(english:"MySQL < 4.0.27 / 4.1.19 / 5.0.21 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
4.0.27 / 4.1.19 / 5.0.21.  As such, it is potentially affected by the
following vulnerabilities :

  - A remote attacker may be able to read portions of memory
    by sending a specially crafted login packet in which the
    username does not have a trailing NULL. (CVE-2006-1516)

  - A remote attacker may be able to read portions of memory
    by sending a specially crafted COM_TABLE_DUMP request 
    with an incorrect packet length. (CVE-2006-1517)

  - A buffer overflow in the 'open_table()' function could 
    allow a remote, authenticated attacker to execute 
    arbitrary code via specially crafted COM_TABLE_DUMP 
    packets. (CVE-2006-1518)");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-0-27.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-1-19.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/432734/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 4.0.27 / 4.1.19 / 5.0.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (!mysql_init(port:port, exit_on_fail:TRUE) == 1) 
  exit(1, "Can't establish a connection to the MySQL server listening on port "+port+".");

version = mysql_get_version();
mysql_close();
if (!strlen(version)) exit(1, "Can't get the version of the MySQL server listening on port "+port+".");

if (
  version =~ "^4\.0\.([01]?[0-9]|2[0-6])($|[^0-9])" ||
  version =~ "^4\.1\.(0?[0-9]|1[0-8])($|[^0-9])" ||
  version =~ "^5\.0\.([01]?[0-9]|20)($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 4.0.27 / 4.1.19 / 5.0.21' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The MySQL "+version+" server listening on port "+port+" is not affected.");

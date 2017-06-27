#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17830);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/01/23 22:42:34 $");

  script_cve_id("CVE-2006-0369");
  script_osvdb_id(27919);

  script_name(english:"MySQL 5.0.18 Information Leak");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information leak
weakness.");

  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host allows local users
to read sensitive information via the following query :

  SELECT * FROM information_schema.views;

This issue is disputed.  Some consider it as a normal behavior for an
SQL database.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/423432/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/423228/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/423204/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/423180/30/7310/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/422491/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/422698/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/422592/100/0/threaded");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport", "Settings/PCI_DSS");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

get_kb_item_or_exit("Settings/PCI_DSS");

port = get_service(svc:'mysql', default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port) >= 0)
{
  # Try to get variant and version
  variant = mysql_get_variant();
  version = mysql_get_version();
}
else exit(0, 'The service on port '+port+' does not look like MySQL.');

if (!version) exit(1, 'Couldn\'t get the MySQL version from the service on port '+port+'.');
if (!variant) variant = 'Unknown';

# Version 5.0.18 is vulnerable
if (version =~ '^5\\.0\\.18([^0-9]|$)')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Variant           : ' + variant +
      '\n  Installed version : ' + version +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}

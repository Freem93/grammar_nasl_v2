#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58274);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/10/01 01:43:20 $");

  script_name(english:"WordPress ToolsPack Plugin Backdoor");
  script_summary(english:"Attempts to execute a command.");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server is affected by a
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A backdoored WordPress installation was detected on the remote host.
The ToolsPack plugin is a backdoor that allows arbitrary code
execution. Its existence suggests that the web server has been
compromised.");
  script_set_attribute(attribute:"see_also", value:"http://blog.sucuri.net/2012/02/new-wordpress-toolspack-plugin.html");
  script_set_attribute(attribute:"solution", value:
"Remove the ToolsPack plugin and do a security review of the web
server, as it has most likely been compromised.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress ToolsPack RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(port:port, qs:dir);

# make an educated guess about which command to run,
# unless paranoid or unable to fingerprint the OS
if (report_paranoia < 2 && (os = get_kb_item('Host/OS')))
{
  if ('Windows' >< os)
    cmds = make_list('ipconfig');
  else
    cmds = make_list('id');
}
else cmds = make_list('id', 'ipconfig');

cmd_pats['id'] = 'uid=[0-9]+.*gid=[0-9]+.*';
cmd_pats['ipconfig'] = 'Windows IP Configuration';

backdoor = dir + '/wp-content/plugins/Toolspack/ToolsPack.php?e=';

foreach cmd (cmds)
{
  php = 'system("' + cmd + '");';
  url = backdoor + base64(str:php);
  res = http_send_recv3(method:'GET', port:port, item:url, exit_on_fail:TRUE);

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      trailer = 'Which resulted in the following output :\n\n' + chomp(res[2]);
      report = get_vuln_report(items:url, port:port, trailer:trailer);
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

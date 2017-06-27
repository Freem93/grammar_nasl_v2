#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23964);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/03/03 18:58:53 $");

  script_bugtraq_id(21823);
  script_osvdb_id(49493);
  script_xref(name:"EDB-ID", value:"3045");

  script_name(english:"Cacti copy_cacti_user.php template_user Variable SQL Injection");
  script_summary(english:"Checks if Cacti's copy_cacti_user.php is remotely accessible");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Cacti, a web-based, front end to RRDTool for
network graphing.

The version of Cacti on the remote host does not properly check
whether the 'copy_cacti_user.php' script is being run from a
commandline and fails to sanitize user-supplied input before using it
in database queries.  Provided PHP's 'register_argc_argv' parameter is
enabled, which is the default, an attacker can leverage this issue to
launch SQL injection attacks against the underlying database and, for
example, add arbitrary administrative users.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:the_cacti_group:cacti");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("cacti_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cacti");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'cacti', port:port, exit_on_fail:TRUE);
dir = install['dir'];

  # Check whether we can pass arguments to the script.
  cgi = strcat(dir, "/copy_cacti_user.php");
  u = strcat(cgi, "?", SCRIPT_NAME);
  r = http_send_recv3(port: port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # There's a problem if we can.
  if ("php copy_cacti_user.php <template user>" >< r[2])
  {
    info = strcat('\nThe vulnerable CGI is reachable at:\n', build_url(port: port, qs: cgi), '\n\n');
    security_hole(port:port, extra: info);
    if (COMMAND_LINE) display(info);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23963);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/03/03 18:58:53 $");

  script_cve_id("CVE-2006-6799");
  script_bugtraq_id(21799);
  script_osvdb_id(31468);
  script_xref(name:"EDB-ID", value:"3029");

  script_name(english:"Cacti cmd.php Multiple Parameter SQL Injection Arbitrary Command Execution");
  script_summary(english:"Checks if Cacti's cmd.php is remotely accessible");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Cacti, a web-based, front end to RRDTool
for network graphing.

The version of Cacti on the remote host does not properly check
to ensure that the 'cmd.php' script is being run from a commandline
and fails to sanitize user-supplied input before using it in database
queries.  Provided PHP's 'register_argc_argv' parameter is enabled,
which is the default, an attacker can launch SQL injection attacks
against the underlying database and even to execute arbitrary code on
the remote host subject to the privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://forums.cacti.net/about18846.html");
  script_set_attribute(attribute:"see_also", value:"http://bugs.cacti.net/view.php?id=883");
  script_set_attribute(attribute:"see_also", value:"http://www.cacti.net/release_notes_0_8_6j.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cacti version 0.8.6j or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/28");
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
  cgi = strcat(dir, "/cmd.php");
  u = strcat(cgi, "?1+1+0");
  r = http_send_recv3(port: port, method: "GET", item: u);
  if (isnull(r)) exit(0);

  # There's a problem if we can.
  if ("Invalid Arguments.  The first argument must be less" >< r[2])
  {
    info = strcat('\nThe vulnerable CGI is reachable at:\n', build_url(port: port, qs: cgi), '\n\n');
    security_hole(port:port, extra: info);
    if (COMMAND_LINE) display(info);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }

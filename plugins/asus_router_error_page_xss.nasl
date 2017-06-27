#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72683);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/25 16:11:33 $");

  script_bugtraq_id(65733);
  script_osvdb_id(103586);

  script_name(english:"ASUS Routers flag Parameter XSS");
  script_summary(english:"Tries to exploit the issue");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web page that is affected by a cross-
site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server fails to sanitize user-supplied input to the
'flag' parameter of the 'error_page.htm' script before using it to
generate dynamic HTML output.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site.

Note that this install is likely affected by an information disclosure
vulnerability, although Nessus has not checked for that."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531194/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Either upgrade to firmware 3.0.0.4.374.4422 or contact the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:asus:rt-n10u_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:asus:rt-n56u_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:asus:dsl-n55u_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:asus:rt-ac66u_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:asus:rt-n15u_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:asus:rt-n53_firmware");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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

title_regex = "<title>ASUS.+ - Error message</title>";
url = '/error_page.htm';
xss = "'+alert('" + SCRIPT_NAME + "')+'";

if (report_paranoia < 2)
{
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (!egrep(pattern:title_regex, string:res[2])) exit(0, "The web server listening on port "+port+" does not appear to be an ASUS router.");
}


exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(""),
  cgi      : url,
  qs       : "flag=" + urlencode(str:xss),
  pass_str : "var casenum = '" + xss + "';",
  ctrl_re  : title_regex
);

if (!exploited) exit(0, "The ASUS router listening on port "+port+" is not affected.");

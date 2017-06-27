#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80555);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_cve_id("CVE-2014-8742");
  script_bugtraq_id(71625);
  script_osvdb_id(115623);

  script_name(english:"Lexmark MarkVision Enterprise ReportDownloadServlet Information Disclosure");
  script_summary(english:"Attempts to exploit the vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to exploit an information disclosure vulnerability in
Lexmark MarkVision Enterprise due to improper handling of user input
to the 'ReportDownloadServlet' servlet. A remote, unauthenticated
attacker can exploit this issue to read arbitrary files");
  script_set_attribute(attribute:"see_also", value:"http://support.lexmark.com/index?page=content&id=TE667");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-411/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lexmark MarkVision Enterprise 2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lexmark:markvision");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("lexmark_markvision_enterprise_detect.nasl");
  script_require_ports("Services/www", 9788);
  script_require_keys("www/lexmark_markvision_enterprise");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"lexmark_markvision_enterprise", exit_if_zero:TRUE);
port = get_http_port(default:9788);

install = get_single_install(
  app_name : "lexmark_markvision_enterprise",
  port     : port
);

dir = install['path'];

test_req = "/reports/test/test";

res = http_send_recv3(
  method: "GET",
  item: dir + test_req,
  port: port,
  exit_on_fail: TRUE
);

if("Could not open ServletContext resource [/reports/test/test]" >< res[2] &&
   "com.lexmark.pssd.app.mve.presentation.flex.reports.ReportDownloadServlet.doGet" >< res[2])
{
  if(report_verbosity > 0)
  {
    report =
      '\nNessus was able to verify the issue exists with the following ' +
      'request :' +
      '\n' +
      '\n' + build_url(port:port, qs:dir + test_req) +
      '\n';
      security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Lexmark MarkVision Enterprise", build_url(qs:dir, port:port));

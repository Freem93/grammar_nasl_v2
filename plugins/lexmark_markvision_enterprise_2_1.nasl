#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80203);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/26 14:38:27 $");

  script_cve_id("CVE-2014-8741", "CVE-2014-8742");
  script_bugtraq_id(71623, 71625);
  script_osvdb_id(115622, 115623);

  script_name(english:"Lexmark MarkVision Enterprise < 2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Lexmark MarkVision Enterprise.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Lexmark MarkVision Enterprise installed on the remote
host is prior to 2.1.0. It is, therefore, affected by the following
vulnerabilities :

  - A remote code execution vulnerability due to improper
    handling of user input to the 'GfdFileUploadServerlet'
    servlet. (CVE-2014-8741)

  - An information disclosure vulnerability due to improper
    handling of user input to the 'ReportDownloadServlet'
    servlet. (CVE-2014-8742)");
  script_set_attribute(attribute:"see_also", value:"http://support.lexmark.com/index?page=content&id=TE667");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-411/");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-14-410/");
  script_set_attribute(attribute:"see_also",value:"http://support.lexmark.com/index?page=content&id=TE666");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lexmark MarkVision Enterprise 2.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Lexmark MarkVision Enterprise 2.0 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Lexmark MarkVision Enterprise Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lexmark:markvision");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("lexmark_markvision_enterprise_detect.nasl");
  script_require_keys("www/lexmark_markvision_enterprise");
  script_require_ports("Services/www", 9788);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9788);

appname = "Lexmark Markvision Enterprise";

install = get_install_from_kb(appname:'lexmark_markvision_enterprise', port:port, exit_on_fail:TRUE);
version = install['ver'];
fixed_ver = "2.1.0";

url = build_url(port:port, qs:install['dir']);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);

if (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);

if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fixed_ver +
           '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

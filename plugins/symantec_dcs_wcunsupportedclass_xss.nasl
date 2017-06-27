#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81552);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_osvdb_id(117515);

  script_name(english:"Symantec Data Center Security Server 'WCUnsupportedClass.jsp' XSS");
  script_summary(english:"Attempts to exploit the cross-site scripting vulnerability.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Symantec Data Center Security Server running on the remote
host is affected by a reflected cross-site scripting vulnerability due
to improper validation of input to the 'classname' parameter in the
'WCUnsupportedClass.jsp' script.");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20150122-0_Symantec_SDCSSA_Multiple_critical_vulnerabilities_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9761dcce");
  script_set_attribute(attribute:"solution", value:
"There is currently no known fix. As a workaround, restrict access to
the application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:critical_system_protection");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8081);
  script_dependencies("symantec_dcs_web_interface_detect.nbin", "http_version.nasl");
  script_require_keys("installed_sw/Symantec Data Center Security Server");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

appname = 'Symantec Data Center Security Server';
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8081);

get_single_install(app_name:appname, port:port);

xss_str = "<script>alert('XSS');</script>";

res = test_cgi_xss(port:port,
                   cgi:"/webui/admin/WCUnsupportedClass.jsp",
                   qs:"classname=" + urlencode(str:xss_str),
                   pass_str:xss_str,
                   ctrl_re:"<title>AjaxSwing 4.0</title>");

if(!res)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:"/webui/apps/sdcss"));

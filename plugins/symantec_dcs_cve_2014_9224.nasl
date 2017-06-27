#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81550);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2014-9224");
  script_bugtraq_id(72093);
  script_osvdb_id(117355);

  script_name(english:"Symantec Data Center Security Server 'SSO-Error.jsp' XSS (SYM15-001)");
  script_summary(english:"Attempts to exploit the cross-site scripting vulnerability.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Symantec Data Center Security Server running on the remote
host is affected by a reflected cross-site scripting vulnerability due
to improper validation of input to the 'ErrorMsg' parameter in the
'/webui/Khaki_docs/SSO-Error.jsp' script.");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150119_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f75a756a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Data Center Security version 6.0 MP1, and apply
the protection policy modifications described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:critical_system_protection");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
                   cgi:"/webui/Khaki_docs/SSO-Error.jsp",
                   qs:"ErrorMsg=" + urlencode(str:xss_str),
                   pass_str:xss_str,
                   ctrl_re:"Your attempt to access the SCSP UI failed due to the following error");

if(!res)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:"/webui/apps/sdcss"));

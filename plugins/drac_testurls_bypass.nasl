#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68905);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id("CVE-2013-4785");
  script_bugtraq_id(60668);
  script_osvdb_id(94323, 95101);

  script_name(english:"Dell iDRAC6 Multiple Vulnerabilities");
  script_summary(english:"Checks for a web page that allows unauthorized access.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Dell Integrated Remote Access Controller 6 (iDRAC6) is
affected by the following vulnerabilities :

  - A flaw exists in the testurls.html page that allows a
    remote attacker to authenticate as root. A remote
    attacker can exploit this to enable root user access
    over SSH, telnet, and other services. (CVE-2013-4785)

  - A flaw exists in the Intelligent Platform Management
    Interface (IPMI) implementation due to improper handling
    of connections. An unauthenticated, remote attacker can
    exploit this to exhaust system resources, resulting in a
    denial of service condition. (VulnDB 94323)");
  script_set_attribute(attribute:"see_also", value:"http://fish2.com/ipmi/dell/secret.html");
  # Patch Download
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cf7ce9b");
  # ftp://ftp.dell.com/Manuals/Common/integrated-dell-remote-access-cntrllr-6-for-monolithic-srvr-v1.95_FAQ2_en-us.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbbee7cf");
  script_set_attribute(attribute:"solution", value:"Upgrade to firmware version 1.95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:idrac6_firmware");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "iDRAC";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];

if (version !~ "^6")
  audit(AUDIT_WRONG_WEB_SERVER, port, "iDRAC6 and therefore is not affected");

url = dir + "/testurls.html";

# Make the request and check for certain elements
res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail: TRUE
);

if (
 "This page contains links that can be used to request XML document directly from the server" >< res[2] &&
 "SSH User" >< res[2] &&
 "Reboot: Click to reboot" >< res[2]
)
{
  report =
    '\nNessus was able to bypass authorization to access the following URL : ' +
    '\n  URL : ' + build_url(qs:url, port:port) +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app + version, build_url(qs:dir, port:port));

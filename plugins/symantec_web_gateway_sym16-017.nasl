#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94052);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/30 15:10:04 $");

  script_cve_id("CVE-2016-5313");
  script_bugtraq_id(93284);
  script_osvdb_id(145242);
  script_xref(name:"IAVA", value:"2016-A-0283");

  script_name(english:"Symantec Web Gateway < 5.2.5 Management Console Command Injection (SYM16-017)");
  script_summary(english:"Checks the SWG version.");

  script_set_attribute(attribute:"synopsis", value:
"A web security application hosted on the remote web server is affected
by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Web
Gateway application hosted on the remote web server is prior to 5.2.5.
It is, therefore, affected by a flaw in the web-based management
console interface, specifically within the /spywall/new_whitelist.php
script, due to improper whitelist validation checks. An authenticated,
remote attacker can exploit this, via a specially crafted request,
to make unauthorized whitelist entries and to execute arbitrary
commands with 'root' privileges.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20161005_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1915d2b9");
  # https://packetstormsecurity.com/files/139006/Symantec-Web-Gateway-5.2.2-OS-Command-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a894618");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Web Gateway version 5.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Web Gateway 5.2.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("installed_sw/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

port = get_http_port(default:443, php:TRUE);
app = 'Symantec Web Gateway';

install = get_single_install(
  app_name : 'symantec_web_gateway',
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
url = build_url(port:port, qs:dir);

fix = '5.2.5';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

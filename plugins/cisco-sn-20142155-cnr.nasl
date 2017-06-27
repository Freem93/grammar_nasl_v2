#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73755);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/29 14:46:26 $");

  script_cve_id("CVE-2014-2155");
  script_bugtraq_id(66975);
  script_osvdb_id(106009);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo07437");

  script_name(english:"Cisco Network Registrar 7.1 DHCPv6 DoS (CSCuo07437)");
  script_summary(english:"Checks CNR version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Cisco Network Registrar (CNR)
7.1. It is, therefore, affected by a denial of service vulnerability
due to a flaw in the DHCPv6 server module. An attacker could
potentially exploit this vulnerability to cause the DHCPv6 server to
reboot.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-2155
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b660e679");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=33850
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?111268ad");
  script_set_attribute(attribute:"see_also",value:"https://tools.cisco.com/bugsearch/bug/CSCuo07437");
  script_set_attribute(attribute:"solution", value:
"Contact normal Cisco support channels to upgrade to a version that
includes a fix for this vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:cns_network_registrar");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_network_registrar_detect.nbin");
  script_require_keys("www/cnr");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/cnr");

port = get_http_port(default:8080);

app_name = "Cisco Network Registrar";
kb_appname = "cnr_ui";
install = get_install_from_kb(appname:kb_appname, port:port, exit_on_fail:FALSE);

if (isnull(install)) audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

report_url = build_url(qs:install['dir'], port:port);
version = install['ver'];

if (version =~ "^7\.1($|\.)" && ver_compare(ver:version, fix:"7.1.3", strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL     : ' + report_url +
      '\n  Version : ' + version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url, version);

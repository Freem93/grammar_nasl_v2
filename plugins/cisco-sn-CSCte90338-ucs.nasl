#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2012-4074. The text itself is
# copyright (C) Cisco.
#

include("compat.inc");

if (description)
{
  script_id(72458);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/12 19:42:54 $");

  script_cve_id("CVE-2012-4074");
  script_bugtraq_id(62455);
  script_osvdb_id(97382);
  script_xref(name:"CISCO-BUG-ID", value:"CSCte90338");

  script_name(english:"Cisco Unified Computing System Serial over LAN Static Private Key Vulnerability (CSCte90338)");
  script_summary(english:"Checks the UCS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the Cisco Unified Computing System Serial over LAN
(SoL) implementation could allow an unauthenticated, remote attacker to
perform a man-in-the-middle (MITM) attack. 

The vulnerability occurs because the Board Management Controller (BMC)
uses a hard-coded private key.  An attacker could exploit this
vulnerability by intercepting an SoL connection.  Successful
exploitation could allow the attacker to view or modify SoL
communications."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2012-4074
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c51806fa");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCte90338.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:unified_computing_system");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("www/cisco_ucs_manager");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'cisco_ucs_manager', port:port, exit_on_fail:TRUE);

url = build_url(qs:install['dir'] + '/', port:port);
version = install['ver'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, 'Cisco UCS Manager', port);

match = eregmatch(pattern:"^([0-9.]+)\(([^)]+)\)", string:version);
if (isnull(match)) exit(1, "Failed to parse the version of Cisco UCS Manager installed at <"+url+">.");

major = match[1];
build = match[2];

if (
  (major == '1.0' && build =~ '^(|Base|2k)$') ||
  (major == '1.1' && build =~ '^(|Base|1m)$') ||
  (major == '1.2' && build =~ '^(|Base|0.9|1d)$') ||
  (major == '1.3' && build =~ '^(|Base)$')
)
{ 
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3(1c)' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);

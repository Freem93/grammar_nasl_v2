#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Advisory cisco-sa-20130424-ucsmulti. The text itself is
# copyright (C) Cisco.
#

include("compat.inc");

if (description)
{
  script_id(69921);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/09/20 14:21:53 $");

  script_cve_id(
    "CVE-2013-1182",
    "CVE-2013-1183",
    "CVE-2013-1184",
    "CVE-2013-1185",
    "CVE-2013-1186"
  );
  script_bugtraq_id(59451, 59453, 59455, 59457, 59459);
  script_osvdb_id(92761, 92763, 92765, 92766, 92767);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtc91207");
  script_xref(name:"IAVA", value:"2013-A-0099");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd32371");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg48206");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq86543");
  script_xref(name:"CISCO-BUG-ID", value:"CSCts53746");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130424-ucsmulti");

  script_name(english:"Multiple Vulnerabilities in Cisco Unified Computing System (cisco-sa-20130424-ucsmulti)");
  script_summary(english:"Checks the UCS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Managed and standalone Cisco Unified Computing System (UCS) deployments
contain one or more of the following vulnerabilities :

  - Cisco Unified Computing System LDAP User Authentication
    Bypass Vulnerability (CVE-2013-1182)

  - Cisco Unified Computing System IPMI Buffer Overflow
    Vulnerability (CVE-2013-1183)

  - Cisco Unified Computing Management API Denial of Service
    Vulnerability (CVE-2013-1184)

  - Cisco Unified Computing System Information Disclosure
    Vulnerability (CVE-2013-1185)

  - Cisco Unified Computing System KVM Authentication Bypass
    Vulnerability (CVE-2013-1186)

Cisco has released free software updates that address these
vulnerabilities."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130424-ucsmulti
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?421a2af8");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to version 2.1.1e as recommended in Cisco Security Advisory
cisco-sa-20130424-ucsmulti."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
  major == '1.0' ||
  major == '1.1' ||
  major == '1.2' ||
  major == '1.3' ||
  major == '1.4' ||
  (major == '2.0' && build =~ '^(0[^0-9]|1[a-w])')
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL                 : ' + url +
      '\n  Installed version   : ' + version +
      '\n  Recommended version : 2.1.1e' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);

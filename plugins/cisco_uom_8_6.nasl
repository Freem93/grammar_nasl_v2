#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56485);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id(
    "CVE-2011-0959",
    "CVE-2011-0960",
    "CVE-2011-0961",
    "CVE-2011-0962",
    "CVE-2011-0966",
    "CVE-2011-2738"
  );
  script_bugtraq_id(47898, 47901, 47903, 49627);
  script_osvdb_id(
    72412,
    72413,
    72414,
    72415,
    72416,
    72417,
    72418,
    72419,
    72420,
    72421,
    75442,
    77172
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCtn42961");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtn61716");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto12704");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto12712");
  script_xref(name:"CISCO-BUG-ID", value:"CSCto35577");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110914-cusm");
  script_xref(name:"EDB-ID", value:"17304");
  script_xref(name:"IAVA", value:"2011-A-0132");

  script_name(english:"Cisco Unified Operations Manager < 8.6 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The monitoring application hosted on the remote web server has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Cisco
Unified Operations Manager on the remote host has multiple
vulnerabilities :

  - Multiple reflected XSS. (CVE-2011-0959, CVE-2011-0961,
    CVE-2011-0962)

  - Multiple blind SQL injections. (CVE-2011-0960)

  - A directory traversal in auditLog.do. (CVE-2011-0966)

  - An unspecified code execution vulnerability.
    (CVE-2011-2738)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.senseofsecurity.com.au/advisories/SOS-11-006");
  script_set_attribute(attribute:"see_also",value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=23085");
  script_set_attribute(attribute:"see_also",value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=23086");
  script_set_attribute(attribute:"see_also",value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=23087");
  # http://www.cisco.com/en/US/products/products_security_advisory09186a0080b9351e.shtml
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b6ed88ce");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Unified Operations Manager 8.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_uom_detect.nasl");
  script_require_keys("www/cisco_uom");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'cisco_uom', port:port, exit_on_fail:TRUE);
login_page = install['dir'] + get_kb_item('/tmp/cuom/' + port + '/loginpage');
login_url = build_url(qs:login_page, port:port);
ver = install['ver'];

if (ver == UNKNOWN_VER)
  exit(1, 'Unable to identify the Cisco Unified Operations Manager version at ' + login_url + '.');

if (ver_compare(ver:ver, fix:'8.6', strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + login_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 8.6\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'The Cisco Unified Operations Manager ' + ver + ' install at ' + login_url + ' is not affected.');


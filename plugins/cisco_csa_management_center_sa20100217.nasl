#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69952);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2010-0146", "CVE-2010-0147", "CVE-2010-0148");
  script_bugtraq_id(38271, 38272, 38273);
  script_osvdb_id(62443, 62444, 62445);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd73275");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd73290");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtb89870");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100217-csa");

  script_name(english:"Multiple Vulnerabilities in Cisco Security Agent (cisco-sa-20100217-csa)");
  script_summary(english:"Checks Management Center for Cisco Security Agents version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an endpoint security application installed that
is potentially affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version identified on the Management Center for Cisco
Agents web interface, the version of Cisco Security Agent installed on
the remote host is affected by multiple vulnerabilities :

  - An unspecified directory traversal vulnerability exists
    in the Management Center. (CVE-2010-0146)

  - An unspecified SQL injection vulnerability exists in the
    Management Center. (CVE-2010-0147)

  - An unspecified denial of service (DoS) vulnerability
    exists in Cisco Security Agent release 5.2.  Note that
    Windows and Sun Solaris versions are not affected by
    this issue. (CVE-2010-0148)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20100217-csa.html");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco Security Agent 5.1.0.117 / 5.2.0.296 / 6.0.1.132 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_csa_management_center_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/cisco_security_agent");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
appname = 'Cisco Security Agent';

install = get_install_from_kb(
  appname : "cisco_security_agent",
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_url);

fix = "";
if (version =~ "^5\.1\." && ver_compare(ver:version, fix:"5.1.0.117") < 0)
  fix  = "5.1.0.117";
else if (version =~ "^5\.2\." && ver_compare(ver:version, fix:"5.2.0.296") < 0)
  fix = "5.2.0.296";
else if (version =~ "^6\.0\." && ver_compare(ver:version, fix:"6.0.1.132") < 0)
  fix = "6.0.1.132";

if (fix)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);

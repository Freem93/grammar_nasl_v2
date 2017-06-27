#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69953);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2011-0364");
  script_bugtraq_id(46420);
  script_osvdb_id(70884);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj51216");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110216-csa");

  script_name(english:"Management Center for Cisco Security Agents Remote Code Execution (cisco-sa-20110216-csa)");
  script_summary(english:"Checks Management Center for Cisco Security Agents version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an endpoint security application installed that is
potentially affected by a remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version identified on the Management Center for Cisco
Agents web interface, the remote host is potentially affected by a
remote code execution vulnerability.  This is due to the 'webagent.exe'
script failing to properly process POST request parameters.  A remote,
unauthenticated attacker can exploit this issue by creating an arbitrary
file with a crafted 'st_upload' request, which the attacker could use to
execute arbitrary code on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20110216-csa.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Cisco Security Agent 6.0.2.145 or later, or apply the
workaround specified in the vendor advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_url);

# nb:Cisco Security Agent software releases 5.1, 5.2, and 6.0 are affected
fix = "6.0.2.145";
if (
  version =~ "^(5\.[12]|6\.0)\." &&
  ver_compare(ver:version, fix:fix, strict:FALSE) < 0
)
{
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

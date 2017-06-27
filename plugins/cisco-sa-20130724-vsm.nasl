#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69856);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/13 02:35:45 $");

  script_cve_id("CVE-2013-3429", "CVE-2013-3430", "CVE-2013-3431");
  script_bugtraq_id(61430, 61431, 61432);
  script_osvdb_id(91210, 91211, 91213);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130724-vsm");
  script_xref(name:"IAVA", value:"2013-A-0148");

  script_name(english:"Cisco Video Surveillance Manager Multiple Vulnerabilities (cisco-sa-20130724-vsm)");
  script_summary(english:"Checks VSM version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Cisco Video
Surveillance Manager installed on the remote host is affected by
multiple vulnerabilities :

  - The application is affected by a directory traversal
    vulnerability because Cisco VSM does not properly
    validate user-supplied input to the
    'monitor/logselect.php' and 'read_log.jsp' scripts.
    This can allow a remote, unauthorized attacker to gain
    access to arbitrary files on the remote host by sending
    a specially crafted request. (CVE-2013-3429)

  - The application allows access to sensitive data without
    requiring authentication.  Data such as configuration,
    monitoring pages archives, and system logs can be
    accessed by attackers without requiring authentication.
    (CVE-2013-3430, CVE-2013-3431)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130724-vsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c348fd4b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Video Surveillance Manager 7.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:video_surveillance_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("cisco_vsm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cisco_vsm");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
app = "Cisco Video Surveillance Management Console";

install = get_install_from_kb(
  appname : "cisco_vsm",
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_url);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 7)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0 \n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit (AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

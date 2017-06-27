#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60140);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/08/28 00:43:13 $");

  script_cve_id("CVE-2011-0390");
  script_bugtraq_id(46520);
  script_osvdb_id(72605);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtj44534");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110223-telepresence-ctms");

  script_name(english:"Cisco TelePresence Multipoint Switch XML-RPC DoS (cisco-sa-20110223-telepresence-ctms)");
  script_summary(english:"Checks CTMS version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The videoconferencing switch running on the remote host has a denial
of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Cisco
TelePresence Multipoint Switch running on the remote host has a denial
of service vulnerability.  Sending a malicious XML-RPC request to TCP
port 9000 could crash the call geometry process.  A remote,
unauthenticated attacker could exploit this to make the device
unusable for future calls."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110223-telepresence-ctms
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f95a1d4");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco TelePresence Multipoint Switch 1.7.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_multipoint_switch_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("cisco_tms_web_detect.nasl");
  script_require_keys("www/cisco_tms");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'cisco_tms', port:port, exit_on_fail:TRUE);
url = build_url(qs:install['dir'], port:port);

if (install['ver'] == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'CTMS', url);

# the advisory explicitly lists vulnerable versions rather than saying everything before 1.7.2 is affected
if (
  install['ver'] !~ "^1\.0\." && # 1.0.x
  install['ver'] !~ "^1\.1\." && # 1.1.x
  install['ver'] !~ "^1\.5\." && # 1.5.x
  install['ver'] !~ "^1\.6\." && # 1.6.x
  install['ver'] !~ "^1\.7\.[01]([^0-9]|$)" # 1.7.0, 1.7.1
)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'CTMS', url, install['ver']);
}

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + install['ver'] +
    '\n  Fixed version     : 1.7.2\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

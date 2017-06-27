#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60139);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/08/28 00:43:13 $");

  script_cve_id(
    "CVE-2011-0379",
    "CVE-2011-0383",
    "CVE-2011-0384",
    "CVE-2011-0385",
    "CVE-2011-0387",
    "CVE-2011-0388",
    "CVE-2011-0389"
  );
  script_bugtraq_id(
    46514, 
    46516, 
    46519, 
    46520, 
    46523
 );
  script_osvdb_id(
    72594,
    72598,
    72599,
    72600,
    72602,
    72603,
    72604
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd75766");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtf01253");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtf42008");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtf97164");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtg35825");
  script_xref(name:"CISCO-BUG-ID", value:"CSCth60993");
  script_xref(name:"CISCO-BUG-ID", value:"CSCth61065");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110223-telepresence-ctms");

  script_name(english:"Cisco TelePresence Multipoint Switch < 1.7.0 Multiple Vulnerabilities (cisco-sa-20110223-telepresence-ctms)");
  script_summary(english:"Checks CTMS version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The videoconferencing switch running on the remote host is affected
by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Cisco
TelePresence Multipoint Switch running on the remote host is earlier
than 1.7.0 and, therefore, has the following vulnerabilities:

  - Servlets used to perform administrative actions are
    accessible without authentication. (CVE-2011-0383,
    CVE-2011-0384, CVE-2011-0387)

  - Unauthenticated attackers can upload files to arbitrary
    locations. (CVE-2011-0385)

  - An unauthenticated attacker on the same network segment
    could send a malicious Cisco Discovery Protocol packet,
    resulting in a buffer overflow. (CVE-2011-0379)

  - Java RMI access is not properly restricted, which could
    allow an unauthenticated, remote attacker to cause a
    denial of service. (CVE-2011-0388)

  - Receiving a malicious RTCP packet could cause the
    call control process to crash. (CVE-2011-0389)
    
A remote, unauthenticated attacker could potentially exploit the most 
severe of these vulnerabilities to take complete control of the host."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110223-telepresence-ctms
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f95a1d4");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco TelePresence Multipoint Switch 1.7.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

# the advisory explicitly lists vulnerable versions rather than saying everything before 1.7.0 is affected
if (
  install['ver'] !~ "^1\.0\." && # 1.0.x
  install['ver'] !~ "^1\.1\." && # 1.1.x
  install['ver'] !~ "^1\.5\." && # 1.5.x
  install['ver'] !~ "^1\.6\."    # 1.6.x
)
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'CTMS', url, install['ver']);
}

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + install['ver'] +
    '\n  Fixed version     : 1.7.0\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);


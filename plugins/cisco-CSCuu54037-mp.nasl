#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84727);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/15 14:48:53 $");

  script_cve_id("CVE-2015-4233");
  script_bugtraq_id(75500);
  script_osvdb_id(123970);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu54037");

  script_name(english:"Cisco Unified MeetingPlace Unspecified SQLi (CSCuu54037)");
  script_summary(english:"Checks the version of Cisco Unified MeetingPlace.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a conferencing application that is
affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Unified
MeetingPlace application hosted on the remote web server is
potentially affected by a SQL injection vulnerability due to a failure
to properly sanitize user-supplied input. An authenticated, remote
attacker can exploit this to manipulate or disclose arbitrary data by
sending a crafted SQL statement to the system.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number. Additionally,
the coarse nature of the version information Nessus gathered is not
enough to confirm that the application is vulnerable, only that it
might be affected.");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=39570
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?666ffc13");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuu54037");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.6(1.537) or greater.

Alternatively, contact the vendor regarding the patch for Cisco bug ID
CSCuu54037.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_meetingplace");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ump_detect.nasl");
  script_require_keys("installed_sw/Cisco Unified MeetingPlace", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

app = "Cisco Unified MeetingPlace";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
dir = install["path"];
ver = install["version"];
url = build_url(port:port, qs:dir);

# Only specifically 8.6(1.2), however 8.6
# is at best all we get from the detect
if (ver !~ "^8\.6(\(1\.2\))?$") audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 8.6(1.537)' +
    '\n  Cisco bug ID      : CSCuu54037'+
    '\n';
}
security_warning(port:port, extra:report);

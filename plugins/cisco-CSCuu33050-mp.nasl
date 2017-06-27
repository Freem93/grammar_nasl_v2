#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84726);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/15 14:48:53 $");

  script_cve_id("CVE-2015-4214");
  script_bugtraq_id(75380);
  script_osvdb_id(123625);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu33050");

  script_name(english:"Cisco Unified MeetingPlace Web Page Source Code Remote Password Disclosure (CSCuu33050)");
  script_summary(english:"Checks the version of Cisco Unified MeetingPlace.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a conferencing application that is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Unified
MeetingPlace application hosted on the remote web server is
potentially affected by an information disclosure vulnerability due to
improper handling of passwords. An authenticated, remote attacker can 
obtain plaintext passwords by viewing the source code of certain HTML
pages.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number. Additionally,
the coarse nature of the version information Nessus gathered is not
enough to confirm that the application is vulnerable, only that it
might be affected.");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=39470
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b78eced");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuu33050");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 8.6(2.5) or greater.

Alternatively, contact the vendor regarding the patch for Cisco bug ID
CSCuu33050.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
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

# Only specifically 8.6(1.2) / 8.6(1.9), however 8.6
# is at best all we get from the detect
if (ver !~ "^8\.6(\(1\.[29]\))?$") audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 8.6(2.5)' +
    '\n  Cisco bug ID      : CSCuu33050'+
    '\n';
}
security_warning(port:port, extra:report);

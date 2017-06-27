#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84193);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/14 14:57:43 $");

  script_cve_id("CVE-2015-0758");
  script_bugtraq_id(74922);
  script_osvdb_id(122760);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus97452");

  script_name(english:"Cisco Unified MeetingPlace XML Processing Information Disclosure (CSCus97452)");
  script_summary(english:"Checks the version of Cisco Unified MeetingPlace.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a conferencing application that is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Unified
MeetingPlace application hosted on the remote web server is
potentially affected by an information disclosure vulnerability due to
improper handling of XML external entities (XXEs). An authenticated,
remote attacker can exploit this vulnerability, by convincing a
MeetingPlace administrator to import a specially crafted XML file, to
disclose sensitive information stored in files on the affected system.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number. Additionally,
the coarse nature of the version information Nessus gathered is not
enough to confirm that the application is vulnerable, only that it
might be affected.");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=39130
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5db8879");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus97452");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus97452.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");

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

# Only specifically 8.6(1.9), however 8.6 is at best all we get from the detect
if (ver !~ "^8\.6(\(1\.9\))?$") audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Cisco bug ID      : CSCus97452'+
    '\n';
}
security_note(port:port, extra:report);

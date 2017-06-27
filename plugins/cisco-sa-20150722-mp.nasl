#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85126);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/03 13:36:06 $");

  script_cve_id("CVE-2015-4262");
  script_bugtraq_id(75996);
  script_osvdb_id(125123);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu51839");
  script_xref(name:"IAVA", value:"2015-A-0178");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150722-mp");

  script_name(english:"Cisco Unified MeetingPlace Web Conferencing Unauthorized Password Change Security Bypass");
  script_summary(english:"Checks the version of Cisco Unified MeetingPlace.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a conferencing application that is
affected by security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Cisco Unified MeetingPlace Web Conferencing hosted on the remote web
server is potentially affected by a security bypass vulnerability due
to the lack of validation of the current password and HTTP session ID
during a password change request. A remote attacker can exploit this,
via a crafted HTTP request, to change the password of an arbitrary
user.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number. Additionally,
the coarse nature of the version information Nessus gathered is not
enough to confirm that the application is vulnerable, only that it
might be affected.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150722-mp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20df73fb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuu51839");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Unified MeetingPlace Web Conferencing version 8.5(5)
MR3 / 8.6(2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_meetingplace_web_conferencing");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

# Note that we only had examples from the Internet to work with, and
# could not get granular version information from them. As a result,
# this check is overly broad.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Cisco Unified MeetingPlace";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
dir = install["path"];
ver = install["version"];
url = build_url(port:port, qs:dir);

fix    = NULL; 
fix_ui = NULL; 

if (ver =~ "^([0-7]\.|8\.[0-5]([^0-9]|$))")
{
  fix    = "8.5.5.49";
  fix_ui = "8.5(5) MR3";
}
else if (ver =~ "^8\.6([^0-9]|$)")
{
  fix    = "8.6.2.9";
  fix_ui = "8.6(2)";
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + ' (' + fix_ui + ')' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

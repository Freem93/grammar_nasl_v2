#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70078);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/08/02 04:39:58 $");

  script_cve_id("CVE-2013-1168", "CVE-2013-1169");
  script_bugtraq_id(59006, 59014);
  script_osvdb_id(92214, 92215);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc64885");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc64846");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130410-mp");

  script_name(english:"Cisco Unified MeetingPlace Multiple Session Weaknesses");
  script_summary(english:"Checks the version of Cisco Unified MeetingPlace.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a conferencing application with
multiple session weaknesses.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Cisco Unified MeetingPlace hosted on the remote web server may be
affected by multiple session weaknesses :

  - The application fails to invalidate a session upon a
    logout action, which makes it easier for remote
    attackers to hijack sessions by leveraging knowledge of
    a session cookie. (CVE-2013-1168)

  - When the 'Remember Me' option is used, the application
    fails to properly verify cookies, which may allow an
    unauthenticated, remote attacker to impersonate users
    via crafted login requests. (CVE-2013-1169)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number. 
Additionally, the coarse nature of the version information Nessus
gathered is not enough to confirm that the application is vulnerable,
only that it might be affected.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130410-mp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d394e551");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7.1MR1 Patch 2 / 8.0MR1 Patch 2 / 8.5MR3 Patch 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_meetingplace");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ump_detect.nasl");
  script_require_keys("installed_sw/Cisco Unified MeetingPlace");
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

# Note that we only had examples from the Internet to work with, and
# could not get granular version information from them. As a result,
# this check is overly broad.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (ver =~ "^7\.[01](\.|$)")
  fix = "7.1MR1 Patch 2";
else if (ver =~ "^8\.0(\.|$)")
  fix = "8.0MR1 Patch 2";
else if (ver =~ "^8\.5(\.|$)")
  fix = "8.5MR3 Patch 1";
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_hole(port:port, extra:report);

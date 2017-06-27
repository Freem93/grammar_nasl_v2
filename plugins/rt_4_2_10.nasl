#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83140);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/30 14:08:21 $");

  script_cve_id("CVE-2014-9472", "CVE-2015-1165", "CVE-2015-1464");
  script_bugtraq_id(72832, 72833, 72837);
  script_osvdb_id(118806, 118807, 118808);

  script_name(english:"Request Tracker 4.0.x < 4.0.23 / 4.2.x < 4.2.10 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Request Tracker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Best Practical
Solutions Request Tracker (RT) running on the remote web server is
version 4.0.x prior to 4.0.23 or version 4.2.x prior to 4.2.10. It is,
therefore, potentially affected by the following vulnerabilities :

  - A flaw exists in the email gateway that allows remote
    attackers to cause a denial of service via a specially
    crafted email. (CVE-2014-9472)
    
  - A flaw exists that allows remote attackers to obtain
    sensitive RSS feed URLs and ticket data via unspecified
    vectors. (CVE-2015-1165)
    
  - A flaw exists in how RSS feed URLs are handled that could
    allow a remote attacker to log in as the user who created
    the feed. (CVE-2015-1464)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.bestpractical.com/release-notes/rt/4.2.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Request Tracker 4.0.23 / 4.2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("rt_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/RT", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "RT";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = install['version'];
path    = install['path'];
install_url = build_url(port:port, qs:path + "/");

if (version =~ "^4\.0\.") fix = '4.0.23';
else if (version =~ "^4\.2\.") fix = '4.2.10';
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);

ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

if (
  (ver[0] == 4 && ver[1] == 0 &&
    (ver[2] < 23) ||
     ver[2] == 23 && version =~ "(rc|pre|alpha|RC|test|CH|beta|preflight)") ||
  (ver[0] == 4 && ver[1] == 2 &&
    (ver[2] < 10) ||
     ver[2] == 10 && version =~ "(rc|pre|alpha|RC|test|CH|beta|preflight)")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);

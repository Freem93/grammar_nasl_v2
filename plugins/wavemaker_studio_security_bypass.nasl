#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60063);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/08/28 00:43:14 $");

  script_bugtraq_id(54196);
  script_osvdb_id(83274);

  script_name(english:"WaveMaker < 6.4.6 Security Bypass");
  script_summary(english:"Checks version of wavemaker studio");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web development application hosted on the remote web server has a
security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of
WaveMaker installed on the remote host has a security bypass
vulnerability.  Any projects deployed with WaveMaker Studio before
6.4.6 are affected by this vulnerability.  A remote attacker could
exploit this by requesting project services using unspecified URLs."
  );
  # http://dev.wavemaker.com/blog/2012/06/22/wavemaker-6-4-6-important-security-update/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32760b3d");
  script_set_attribute(attribute:"see_also", value:"http://dev.wavemaker.com/wiki/bin/wmdoc_6.4/WM646RelNotes");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to WaveMaker 6.4.6 or later.

Existing projects should be redeployed by WaveMaker Studio 6.4.6 or
later in order to address this issue.  If redeployment is not
possible, consider the workaround referenced in the WaveMaker 6.4.6
release notes."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:wavemaker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("wavemaker_studio_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/wavemaker_studio");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8094);
install = get_install_from_kb(appname:'wavemaker_studio', port:port, exit_on_fail:TRUE);
url = build_url(qs:install['dir'], port:port);

if (install['ver'] == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Wavemaker Studio', url);

fix = '6.4.6';

# the detection plugin ensures the version is all numeric
if (ver_compare(ver:install['ver'], fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'WaveMaker Studio', url, install['ver']);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + install['ver'] +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

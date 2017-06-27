#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18245);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/09/22 17:06:55 $");

  script_cve_id("CVE-2005-1563", "CVE-2005-1564", "CVE-2005-1565");
  script_bugtraq_id(13605, 13606);
  script_osvdb_id(16425, 16426, 16427);

  script_name(english:"Bugzilla < 2.18.1 Multiple Information Disclosures");
  script_summary(english:"Checks Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that suffers from
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
Bugzilla that reportedly may include passwords in the web server logs
because it embeds a user's password in a report URL if the user is
prompted to log in while viewing a chart. It also allows users to
learn whether an invisible product exists in Bugzilla because the
application uses one error message if it does not and another if it
does but access is denied. And finally, it lets users enter bugs even
when the bug entry is closed provided a valid product name is used.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/2.16.8/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 2.18.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

# Check the installed version.
install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
dir = install['path'];
install_loc = build_url(port:port, qs:dir+'/query.cgi');

if (version =~ "^2\.([0-9]\..*|1[0-9]$|1[0-5]\..*|16\.[0-8][^0-9]?|17\..*|18\.0|19\.[0-2][^0-9]?)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version : ' + version +
      '\n  URL     : ' + install_loc;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);

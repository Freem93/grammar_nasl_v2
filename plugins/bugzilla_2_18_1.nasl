#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18654);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/09/22 17:06:55 $");

  script_cve_id("CVE-2005-2173", "CVE-2005-2174");
  script_bugtraq_id(14198, 14200);
  script_osvdb_id(17800, 17801);

  script_name(english:"Bugzilla <= 2.18.1 / 2.19.3 Multiple Vulnerabilities (ID, more)");
  script_summary(english:"Checks Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that suffers from
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host reportedly allows any user to change any flag on a bug,
even if they don't otherwise have access to the bug or rights to make
changes to it. In addition, a private bug summary may be visible to
users if MySQL replication is used on the backend database.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/2.18.1/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 2.18.2 / 2.20rc1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/08");

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

if (version =~ "^2\.1(7\..*|8\.[01]|9\.[0-3])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version : ' + version +
      '\n  URL     : ' + install_loc +
      '\n  Fix     : 2.18.2 / 2.20rc1';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
